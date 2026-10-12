"""
S3 abstraction layer for retention cold-storage.

Two backends share the same interface:
  - S3LocalBackend: MinIO local on Hestia (or any self-hosted MinIO)
  - S3CloudBackend: AWS S3 / Scaleway Object Storage / OVH / any S3-compatible

The choice is made at runtime from S3_LOCAL env var (or config.yaml
section `retention.s3.local`). Both backends use the same client
library (boto3) — the difference is:
  - Local:  path-style addressing, no region required, custom endpoint URL
  - Cloud:  virtual-hosted style, region required, optional SSE-KMS

Adding a new backend (e.g. Azure Blob, GCP Cloud Storage) is a matter
of subclassing `S3Backend` and implementing the 4 abstract methods.
"""
import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator, Optional

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError, EndpointConnectionError, BotoCoreError

logger = logging.getLogger("logsoc.retention.s3")


@dataclass
class ArchiveObject:
    """Metadata for an archived object — returned by list_objects()."""
    key: str
    size_bytes: int
    last_modified: datetime
    etag: str
    storage_class: str
    metadata: dict


@dataclass
class S3Config:
    """Validated S3 configuration shared by both backends.

    Either S3Config.local() or S3Config.cloud() should be called from
    load_s3_config() — they enforce slightly different invariants.
    """
    endpoint: str
    access_key: str
    secret_key: str
    bucket_logs: str
    bucket_yara: str
    region: str = "us-east-1"
    path_style: bool = True
    use_ssl: bool = True
    verify_ssl: bool = True
    sse_algorithm: Optional[str] = None  # None | 'AES256' | 'aws:kms'
    sse_kms_key_id: Optional[str] = None  # required if sse_algorithm='aws:kms'

    @classmethod
    def local(cls, endpoint, access_key, secret_key, bucket_logs, bucket_yara,
              use_ssl=False) -> "S3Config":
        """MinIO local — no region, path-style, no SSL by default."""
        return cls(
            endpoint=endpoint,
            access_key=access_key,
            secret_key=secret_key,
            bucket_logs=bucket_logs,
            bucket_yara=bucket_yara,
            region="us-east-1",   # MinIO accepts any region
            path_style=True,      # MinIO uses path-style
            use_ssl=use_ssl,
            verify_ssl=False,     # self-signed certs are common
        )

    @classmethod
    def cloud(cls, endpoint, access_key, secret_key, bucket_logs, bucket_yara,
              region, sse_algorithm: Optional[str] = "AES256",
              sse_kms_key_id: Optional[str] = None) -> "S3Config":
        """AWS / Scaleway / OVH — virtual-hosted style, region required."""
        return cls(
            endpoint=endpoint,
            access_key=access_key,
            secret_key=secret_key,
            bucket_logs=bucket_logs,
            bucket_yara=bucket_yara,
            region=region,
            path_style=False,     # cloud uses virtual-hosted
            use_ssl=True,
            verify_ssl=True,
            sse_algorithm=sse_algorithm,
            sse_kms_key_id=sse_kms_key_id,
        )


class S3Backend(ABC):
    """Abstract base — implement these for a new backend."""

    def __init__(self, cfg: S3Config):
        self.cfg = cfg
        self._client = None

    @property
    def client(self):
        """Lazy boto3 client (thread-safe, created on first use)."""
        if self._client is None:
            self._client = boto3.client(
                "s3",
                endpoint_url=self.cfg.endpoint if self.cfg.endpoint else None,
                aws_access_key_id=self.cfg.access_key,
                aws_secret_access_key=self.cfg.secret_key,
                region_name=self.cfg.region,
                config=Config(
                    signature_version="s3v4",
                    s3={
                        "addressing_style": "path" if self.cfg.path_style else "virtual",
                    },
                ),
                verify=self.cfg.verify_ssl,
            )
        return self._client

    @abstractmethod
    def backend_name(self) -> str:
        """'minio-local' or 'aws-s3' or 'scaleway' etc — for logs."""

    def pick_bucket(self, domain: str) -> str:
        """Map a data_domain to its bucket name."""
        if domain in ("yara_rules", "yara_scan_results"):
            return self.cfg.bucket_yara
        return self.cfg.bucket_logs

    def healthcheck(self) -> dict:
        """Returns a dict with 'ok', 'backend', 'endpoint', 'buckets'.

        Use this from /api/v1/system/health and the sidecar's daily check.
        """
        result = {
            "backend": self.backend_name(),
            "endpoint": self.cfg.endpoint,
            "ok": False,
            "buckets": [],
            "error": None,
        }
        try:
            response = self.client.list_buckets()
            result["buckets"] = [b["Name"] for b in response.get("Buckets", [])]
            result["ok"] = True
        except (ClientError, EndpointConnectionError, BotoCoreError) as e:
            result["error"] = str(e)
            logger.warning("S3 healthcheck failed: %s", e)
        return result

    def ensure_bucket(self, bucket: str) -> bool:
        """Create the bucket if it doesn't exist. Returns True if created."""
        try:
            self.client.head_bucket(Bucket=bucket)
            return False  # already exists
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("404", "NoSuchBucket", "NotFound"):
                # Create
                kwargs = {"Bucket": bucket}
                if self.cfg.region != "us-east-1" and not self.cfg.path_style:
                    kwargs["CreateBucketConfiguration"] = {
                        "LocationConstraint": self.cfg.region,
                    }
                self.client.create_bucket(**kwargs)
                logger.info("created S3 bucket %r in %s", bucket, self.backend_name())
                return True
            raise

    def put_object(self, bucket: str, key: str, data: bytes,
                   content_type: str = "application/octet-stream",
                   metadata: Optional[dict] = None) -> str:
        """Upload data. Returns the etag."""
        kwargs = {
            "Bucket": bucket,
            "Key": key,
            "Body": data,
            "ContentType": content_type,
        }
        if metadata:
            kwargs["Metadata"] = {k: str(v)[:1024] for k, v in metadata.items()}
        if self.cfg.sse_algorithm:
            if self.cfg.sse_algorithm == "aws:kms" and self.cfg.sse_kms_key_id:
                kwargs["ServerSideEncryption"] = "aws:kms"
                kwargs["SSEKMSKeyId"] = self.cfg.sse_kms_key_id
            else:
                kwargs["ServerSideEncryption"] = self.cfg.sse_algorithm
        response = self.client.put_object(**kwargs)
        return response.get("ETag", "").strip('"')

    def get_object(self, bucket: str, key: str) -> bytes:
        """Download data. Raises ClientError if not found."""
        response = self.client.get_object(Bucket=bucket, Key=key)
        return response["Body"].read()

    def list_objects(self, bucket: str, prefix: str = "",
                     max_keys: int = 1000) -> Iterator[ArchiveObject]:
        """Iterate over objects in a bucket (paginated)."""
        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(
            Bucket=bucket, Prefix=prefix, PaginationConfig={"MaxItems": max_keys}
        ):
            for obj in page.get("Contents", []):
                yield ArchiveObject(
                    key=obj["Key"],
                    size_bytes=obj["Size"],
                    last_modified=obj["LastModified"],
                    etag=obj["ETag"].strip('"'),
                    storage_class=obj.get("StorageClass", "STANDARD"),
                    metadata=obj.get("Metadata", {}),
                )

    def delete_object(self, bucket: str, key: str) -> None:
        self.client.delete_object(Bucket=bucket, Key=key)


class S3LocalBackend(S3Backend):
    """MinIO (or any self-hosted S3-compatible) on Hestia LAN."""

    def backend_name(self) -> str:
        return "minio-local"


class S3CloudBackend(S3Backend):
    """AWS S3 / Scaleway / OVH / any cloud S3."""

    def backend_name(self) -> str:
        ep = (self.cfg.endpoint or "").lower()
        if "amazonaws.com" in ep:
            return "aws-s3"
        if "scw.cloud" in ep or "scaleway" in ep:
            return "scaleway"
        if "ovh" in ep or "cloud.ovh" in ep:
            return "ovh"
        if "wasabi" in ep:
            return "wasabi"
        if "backblaze" in ep:
            return "backblaze-b2"
        if "digitaloceanspaces" in ep:
            return "digitalocean-spaces"
        return "s3-cloud"


def load_s3_config() -> S3Config:
    """Build the S3Config from config.yaml (T64.1.7: single source of truth).

    Decides local vs cloud via s3.local in config.yaml.
    """
    from app.config_loader import get

    is_local = bool(get("s3.local", False))
    endpoint = str(get("s3.endpoint", ""))
    access_key = str(get("s3.access_key", ""))
    secret_key = str(get("s3.secret_key", ""))
    bucket_logs = str(get("s3.buckets.hot", "logsoc-archives"))
    bucket_yara = str(get("s3.buckets.warm", "logsoc-yara"))

    if is_local:
        use_ssl = bool(get("s3.use_ssl", False))
        return S3Config.local(
            endpoint=endpoint,
            access_key=access_key,
            secret_key=secret_key,
            bucket_logs=bucket_logs,
            bucket_yara=bucket_yara,
            use_ssl=use_ssl,
        )

    region = str(get("s3.region", "us-east-1"))
    sse_algo = str(get("s3.sse_algorithm", "AES256"))
    sse_algo = None if sse_algo.lower() in ("none", "null", "") else sse_algo
    sse_kms = get("s3.sse_kms_key_id", None)
    return S3Config.cloud(
        endpoint=endpoint,
        access_key=access_key,
        secret_key=secret_key,
        bucket_logs=bucket_logs,
        bucket_yara=bucket_yara,
        region=region,
        sse_algorithm=sse_algo or "AES256",
        sse_kms_key_id=sse_kms,
    )


def get_s3_backend() -> S3Backend:
    """Factory: returns the right backend based on config."""
    cfg = load_s3_config()
    from app.config_loader import get
    if bool(get("s3.local", False)):
        return S3LocalBackend(cfg)
    return S3CloudBackend(cfg)
