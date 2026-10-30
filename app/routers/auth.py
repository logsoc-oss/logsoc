from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, UTC
from jose import jwt, JWTError
import bcrypt as _bcrypt
import pyotp
import qrcode
import io
import base64
import secrets
import ipaddress
import logging
from typing import Optional
from app.database import get_db
from app.models import User, RolePermission, UserMfa, SsoConfig, UserSsoLink, LoginAudit, Alert
from app.schemas import UserLogin, Token, RefreshRequest, MessageResponse
from app.config import JWT_SECRET, JWT_EXPIRE_HOURS, JWT_REFRESH_EXPIRE_DAYS, JWT_ALGORITHM
from app.config_loader import get as cfg_get
from pydantic import BaseModel

logger = logging.getLogger("logsoc.auth")

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

# ── In-memory token blacklist (for logout) ──
_blacklisted_tokens: set = set()

# ── In-memory store for MFA temp tokens (short-lived) ──
# In production, use Redis with TTL. Key: token, Value: user_id
_mfa_temp_tokens: dict = {}


# ══════════════════════════════════════════════════════════════════════════
# Helper: login audit logging
# ══════════════════════════════════════════════════════════════════════════

def _audit_login(db: Session, username: str, source_ip: str, user_agent: str | None,
                 status: str, user_id: int | None = None, mfa_used: bool = False):
    """Record a login attempt in login_audit table."""
    try:
        entry = LoginAudit(
            user_id=user_id,
            username=username,
            source_ip=source_ip,
            user_agent=user_agent,
            status=status,
            mfa_used=mfa_used,
        )
        db.add(entry)
        db.commit()
    except Exception as e:
        logger.warning("Failed to write login audit: %s", e)
        db.rollback()


# ══════════════════════════════════════════════════════════════════════════
# Helper: trusted subnets / unknown LAN detection
# ══════════════════════════════════════════════════════════════════════════

def get_trusted_subnets() -> list[str]:
    """Return list of trusted subnet CIDR strings from config, with defaults."""
    subnets = cfg_get("trusted_subnets", None)
    if subnets and isinstance(subnets, list):
        return subnets
    # Defaults
    return ["192.168.0.0/16", "10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12"]


def is_ip_trusted(ip: str, subnets: list[str]) -> bool:
    """Check if an IP is within any trusted subnet."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for subnet in subnets:
            if ip_obj in ipaddress.ip_network(subnet, strict=False):
                return True
    except (ValueError, TypeError):
        pass
    return False


def _check_unknown_lan(db: Session, username: str, source_ip: str, user_id: int):
    """If IP is not in trusted subnets, create an alert and audit entry."""
    subnets = get_trusted_subnets()
    if not is_ip_trusted(source_ip, subnets):
        # Log as unknown_lan in login_audit
        _audit_login(db, username=username, source_ip=source_ip, user_agent=None,
                     status="unknown_lan", user_id=user_id, mfa_used=False)
        # Create alert
        try:
            alert_id = f"LAN-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-{user_id}"
            alert = Alert(
                alert_id=alert_id,
                severity="high",
                status="new",
                title=f"Connexion depuis un LAN inconnu: {username}",
                description=f"L'utilisateur {username} s'est connecté depuis {source_ip} qui n'est pas dans les LANs de confiance.",
                source_host=source_ip,
            )
            db.add(alert)
            db.commit()
            logger.warning("Unknown LAN login detected: user=%s ip=%s", username, source_ip)
        except Exception as e:
            logger.warning("Failed to create unknown LAN alert: %s", e)
            db.rollback()


# ══════════════════════════════════════════════════════════════════════════
# Helper: MFA policy
# ══════════════════════════════════════════════════════════════════════════

def _get_mfa_policy() -> dict:
    """Read MFA policy from config.yaml."""
    return {
        "required": cfg_get("mfa.required", False),
        "enforce_for_roles": cfg_get("mfa.enforce_for_roles", ["admin"]),
    }


def _should_force_mfa_setup(user: User) -> bool:
    """Check if MFA setup should be forced for this user based on global policy."""
    policy = _get_mfa_policy()
    # If user already has mfa_setup_required flag, honor it
    if getattr(user, 'mfa_setup_required', False):
        return True
    # If global policy requires MFA for all
    if policy["required"]:
        return True
    # If global policy requires MFA for specific roles
    if user.role in policy["enforce_for_roles"]:
        return True
    return False


# ══════════════════════════════════════════════════════════════════════════
# JWT helpers
# ══════════════════════════════════════════════════════════════════════════

def create_access_token(user_id: int, role: str) -> str:
    expire = datetime.now(UTC) + timedelta(hours=JWT_EXPIRE_HOURS)
    return jwt.encode(
        {"sub": str(user_id), "role": role, "type": "access", "exp": expire},
        JWT_SECRET, algorithm=JWT_ALGORITHM
    )


def create_refresh_token(user_id: int) -> str:
    expire = datetime.now(UTC) + timedelta(days=JWT_REFRESH_EXPIRE_DAYS)
    return jwt.encode(
        {"sub": str(user_id), "type": "refresh", "exp": expire},
        JWT_SECRET, algorithm=JWT_ALGORITHM
    )


def create_mfa_temp_token(user_id: int) -> str:
    """Create a short-lived token for MFA login flow (5 min TTL)."""
    token = secrets.token_urlsafe(32)
    _mfa_temp_tokens[token] = {
        "user_id": user_id,
        "expires": datetime.now(UTC) + timedelta(minutes=5),
    }
    return token


def verify_mfa_temp_token(token: str) -> Optional[int]:
    """Return user_id if temp token is valid, else None. Cleans up expired."""
    # Purge expired tokens
    now = datetime.now(UTC)
    expired_keys = [k for k, v in _mfa_temp_tokens.items() if v["expires"] < now]
    for k in expired_keys:
        del _mfa_temp_tokens[k]

    data = _mfa_temp_tokens.get(token)
    if not data:
        return None
    if data["expires"] < now:
        del _mfa_temp_tokens[token]
        return None
    return data["user_id"]


def verify_password(user: User, password: str) -> bool:
    """Check plaintext password against stored bcrypt hash."""
    try:
        pwhash = user.password_hash
        if pwhash.startswith("$2y$"):
            pwhash = pwhash.replace("$2y$", "$2b$", 1)
        return _bcrypt.checkpw(password.encode(), pwhash.encode())
    except Exception:
        return False


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise credentials_exception
        user_id: int = int(payload.get("sub"))
    except (JWTError, ValueError):
        raise credentials_exception
    
    if token in _blacklisted_tokens:
        raise credentials_exception
    
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise credentials_exception
    return user


def require_role(*roles: str):
    """Allow listed roles + superadmin (hierarchical: superadmin always passes)."""
    allowed = set(roles) | {'superadmin'}
    def checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user
    return checker


def require_permission(module: str, action: str = 'read'):
    """Dependency factory: check granular RBAC permission for (module, action).

    Actions: 'read' → can_read, 'write' → can_write, 'delete' → can_delete, 'export' → can_export.
    Superadmin always passes regardless of row presence.
    """
    _action_map = {
        'read': RolePermission.can_read,
        'write': RolePermission.can_write,
        'delete': RolePermission.can_delete,
        'export': RolePermission.can_export,
    }
    if action not in _action_map:
        raise ValueError(f"Invalid action '{action}'. Must be one of: read, write, delete, export")

    perm_col = _action_map[action]

    def checker(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> User:
        # Superadmin always passes
        if current_user.role == 'superadmin':
            return current_user

        # Garde module désactivé (13/09): 503 avant la permission granulaire
        from app.module_registry import check_module_enabled
        check_module_enabled(db, current_user, module)

        perm = db.query(RolePermission).filter(
            RolePermission.role == current_user.role,
            RolePermission.module == module,
        ).first()

        if not perm:
            raise HTTPException(status_code=403, detail=f"No permissions for module '{module}'")
        # action='read' -> colonne can_read (fix 13/09: getattr(perm, 'read')
        # etait toujours False — la garde n'avait jamais ete cablee, le bug
        # etait latent depuis la Phase 1)
        if not getattr(perm, f"can_{action}", False):
            raise HTTPException(status_code=403, detail=f"Permission denied: {action} on {module}")
        return current_user

    return checker


# ══════════════════════════════════════════════════════════════════════════
# Helper: extract client IP from request
# ══════════════════════════════════════════════════════════════════════════

def _get_client_ip(request: Request) -> str:
    """Extract client IP, respecting X-Forwarded-For proxy headers."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


# ══════════════════════════════════════════════════════════════════════════
# Auth endpoints (login / refresh / logout)
# ══════════════════════════════════════════════════════════════════════════

@router.post(
    "/login",
    response_model=Token,
    summary="Authenticate user",
    description="Login with username/password. Returns access + refresh JWT tokens. "
    "If MFA is required or setup is required, returns a temp_token instead.",
    responses={401: {"description": "Invalid credentials"}, 403: {"description": "Account disabled"}},
)
def login(payload: UserLogin, request: Request, db: Session = Depends(get_db)):
    source_ip = _get_client_ip(request)
    user_agent = request.headers.get("user-agent", None)

    user = db.query(User).filter(User.username == payload.username).first()
    if not user:
        _audit_login(db, payload.username, source_ip, user_agent, "unknown_user")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.is_active:
        _audit_login(db, payload.username, source_ip, user_agent, "account_locked", user_id=user.id)
        raise HTTPException(status_code=403, detail="Account disabled")
    
    if not verify_password(user, payload.password):
        _audit_login(db, payload.username, source_ip, user_agent, "invalid_password", user_id=user.id)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Check MFA status
    mfa = db.query(UserMfa).filter(UserMfa.user_id == user.id).first()
    mfa_enabled = mfa and mfa.enabled
    force_setup = _should_force_mfa_setup(user)

    if mfa_enabled:
        # MFA is active — need TOTP code
        temp_token = create_mfa_temp_token(user.id)
        _audit_login(db, payload.username, source_ip, user_agent, "mfa_required", user_id=user.id)
        return {
            "access_token": "",
            "refresh_token": "",
            "token_type": "bearer",
            "mfa_required": True,
            "temp_token": temp_token,
        }
    
    if force_setup and not mfa_enabled:
        # Global policy requires MFA but user hasn't set it up yet
        temp_token = create_mfa_temp_token(user.id)
        _audit_login(db, payload.username, source_ip, user_agent, "mfa_setup_required", user_id=user.id)
        return {
            "access_token": "",
            "refresh_token": "",
            "token_type": "bearer",
            "mfa_setup_required": True,
            "temp_token": temp_token,
        }

    # Successful login without MFA
    user.last_login_at = datetime.now(UTC)
    db.commit()
    
    # Check for unknown LAN
    _check_unknown_lan(db, payload.username, source_ip, user.id)
    
    _audit_login(db, payload.username, source_ip, user_agent, "success", user_id=user.id)
    
    access = create_access_token(user.id, user.role)
    refresh = create_refresh_token(user.id)
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}


@router.post(
    "/refresh",
    response_model=Token,
    summary="Refresh access token",
    description="Exchange a valid refresh token for a new access/refresh pair. "
    "The old refresh token is blacklisted (rotation).",
    responses={401: {"description": "Invalid or expired refresh token"}},
)
def refresh_token(payload: RefreshRequest, db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
    )
    try:
        data = jwt.decode(payload.refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if data.get("type") != "refresh":
            raise credentials_exception
        user_id = int(data.get("sub"))
    except (JWTError, ValueError):
        raise credentials_exception
    
    if payload.refresh_token in _blacklisted_tokens:
        raise credentials_exception
    
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise credentials_exception
    
    # Blacklist old refresh token (rotation)
    _blacklisted_tokens.add(payload.refresh_token)
    
    access = create_access_token(user.id, user.role)
    refresh = create_refresh_token(user.id)
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Logout user",
    description="Blacklist the current access token. The client should discard both tokens.",
)
def logout(current_user: User = Depends(get_current_user), token: str = Depends(oauth2_scheme)):
    _blacklisted_tokens.add(token)
    return {"message": "Logged out successfully"}


# ══════════════════════════════════════════════════════════════════════════
# Phase 1.2 — MFA (TOTP) endpoints
# ══════════════════════════════════════════════════════════════════════════

class MfaSetupRequest(BaseModel):
    password: str


class MfaVerifyRequest(BaseModel):
    code: str


class MfaDisableRequest(BaseModel):
    password: str


class MfaLoginRequest(BaseModel):
    temp_token: str
    code: str


class MfaBackupCodesRequest(BaseModel):
    user_id: Optional[int] = None  # Optional: admin can specify another user


class MfaRegenerateRequest(BaseModel):
    code: str  # Current TOTP code to confirm regeneration


def _generate_backup_codes(count: int = 10) -> list[str]:
    """Generate cryptographically random 8-character backup codes."""
    return [secrets.token_hex(4).upper() for _ in range(count)]


@router.post(
    "/mfa/setup",
    summary="Setup MFA — generate TOTP secret and QR code",
    description="Requires current password verification. Returns TOTP secret, "
    "QR code data URL, and 10 backup codes. MFA is NOT enabled until /mfa/verify is called.",
)
def mfa_setup(
    payload: MfaSetupRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Verify current password
    if not verify_password(current_user, payload.password):
        raise HTTPException(status_code=401, detail="Invalid password")

    # Generate TOTP secret
    totp = pyotp.TOTP(pyotp.random_base32())
    secret = totp.secret

    # Generate backup codes
    backup_codes = _generate_backup_codes()

    # Create or update MFA record (not enabled yet)
    mfa = db.query(UserMfa).filter(UserMfa.user_id == current_user.id).first()
    if mfa:
        mfa.secret = secret
        mfa.backup_codes = backup_codes
        # Keep enabled state as-is (may be re-setting up after disable)
    else:
        mfa = UserMfa(
            user_id=current_user.id,
            secret=secret,
            backup_codes=backup_codes,
            enabled=False,
        )
        db.add(mfa)
    db.commit()
    db.refresh(mfa)

    # Generate QR code data URL
    provisioning_uri = totp.provisioning_uri(
        name=current_user.email,
        issuer_name="LogSOC"
    )
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_data_url = f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode()}"

    return {
        "secret": secret,
        "qr_code_url": qr_data_url,
        "backup_codes": backup_codes,
    }


@router.post(
    "/mfa/verify-setup",
    summary="Verify TOTP code and enable MFA (setup completion)",
    description="Verifies a TOTP code against the stored secret. If valid, enables MFA. "
    "Must be called after /mfa/setup to complete MFA enrollment. "
    "Can also be called with a temp_token when forced MFA setup is required.",
)
def mfa_verify_setup(
    payload: MfaVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Support both authenticated and temp_token flows
    # If current_user is provided via Bearer token, use it; otherwise not required
    user = current_user
    
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    mfa = db.query(UserMfa).filter(UserMfa.user_id == user.id).first()
    if not mfa:
        raise HTTPException(status_code=400, detail="MFA not set up. Call /mfa/setup first.")

    totp = pyotp.TOTP(mfa.secret)
    if not totp.verify(payload.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    mfa.enabled = True
    mfa.enabled_at = datetime.now(UTC)
    mfa.last_used_at = datetime.now(UTC)
    # Clear mfa_setup_required flag
    user.mfa_setup_required = False
    db.commit()

    return {"enabled": True}




@router.post(
    "/mfa/verify",
    summary="Verify TOTP code and enable MFA",
    description="Verifies a TOTP code against the stored secret. If valid, enables MFA. "
    "Must be called after /mfa/setup to complete MFA enrollment.",
)
def mfa_verify(
    payload: MfaVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    mfa = db.query(UserMfa).filter(UserMfa.user_id == current_user.id).first()
    if not mfa:
        raise HTTPException(status_code=400, detail="MFA not set up. Call /mfa/setup first.")

    totp = pyotp.TOTP(mfa.secret)
    if not totp.verify(payload.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    mfa.enabled = True
    mfa.enabled_at = datetime.now(UTC)
    mfa.last_used_at = datetime.now(UTC)
    # Clear mfa_setup_required flag
    current_user.mfa_setup_required = False
    db.commit()

    return {"enabled": True}


@router.post(
    "/mfa/regenerate",
    summary="Regenerate MFA secret (renew MFA)",
    description="Generates a new TOTP secret, QR code, and backup codes. "
    "If MFA is already enabled, requires the current TOTP code for confirmation.",
)
def mfa_regenerate(
    payload: MfaRegenerateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    mfa = db.query(UserMfa).filter(UserMfa.user_id == current_user.id).first()

    # If MFA is enabled, verify current code first
    if mfa and mfa.enabled:
        totp = pyotp.TOTP(mfa.secret)
        if not totp.verify(payload.code, valid_window=1):
            raise HTTPException(status_code=401, detail="Invalid current TOTP code")

    # Generate new TOTP secret
    new_totp = pyotp.TOTP(pyotp.random_base32())
    new_secret = new_totp.secret
    new_backup_codes = _generate_backup_codes()

    if mfa:
        mfa.secret = new_secret
        mfa.backup_codes = new_backup_codes
        # Keep enabled state
    else:
        mfa = UserMfa(
            user_id=current_user.id,
            secret=new_secret,
            backup_codes=new_backup_codes,
            enabled=False,
        )
        db.add(mfa)

    db.commit()
    db.refresh(mfa)

    # Generate QR code
    provisioning_uri = new_totp.provisioning_uri(
        name=current_user.email,
        issuer_name="LogSOC"
    )
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_data_url = f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode()}"

    return {
        "secret": new_secret,
        "qr_code_url": qr_data_url,
        "backup_codes": new_backup_codes,
    }


@router.post(
    "/mfa/disable",
    summary="Disable MFA",
    description="Requires current password verification. Disables MFA for the authenticated user.",
)
def mfa_disable(
    payload: MfaDisableRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(current_user, payload.password):
        raise HTTPException(status_code=401, detail="Invalid password")

    mfa = db.query(UserMfa).filter(UserMfa.user_id == current_user.id).first()
    if not mfa or not mfa.enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")

    mfa.enabled = False
    mfa.enabled_at = None
    db.commit()

    return {"enabled": False}


@router.get(
    "/mfa/status",
    summary="Get current user's MFA status",
    description="Returns whether MFA is enabled for the authenticated user.",
)
def mfa_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    mfa = db.query(UserMfa).filter(UserMfa.user_id == current_user.id).first()
    policy = _get_mfa_policy()
    return {
        "enabled": mfa.enabled if mfa else False,
        "last_used_at": mfa.last_used_at.isoformat() if mfa and mfa.last_used_at else None,
        "setup_required": bool(getattr(current_user, 'mfa_setup_required', False)) or _should_force_mfa_setup(current_user),
        "policy_required": policy["required"],
        "policy_roles": policy["enforce_for_roles"],
    }


@router.post(
    "/mfa/backup-codes",
    summary="Regenerate MFA backup codes",
    description="Regenerates 10 backup codes. Admin can specify user_id for another user, "
    "or omit to regenerate for self.",
)
def mfa_backup_codes(
    payload: MfaBackupCodesRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    target_user_id = payload.user_id if payload.user_id else current_user.id

    # Only admin/superadmin can regenerate for other users
    if target_user_id != current_user.id and current_user.role not in ('superadmin', 'admin'):
        raise HTTPException(status_code=403, detail="Cannot regenerate backup codes for other users")

    mfa = db.query(UserMfa).filter(UserMfa.user_id == target_user_id).first()
    if not mfa or not mfa.enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled for this user")

    new_codes = _generate_backup_codes()
    mfa.backup_codes = new_codes
    db.commit()

    return {"backup_codes": new_codes}


@router.post(
    "/mfa/login",
    summary="Complete MFA login",
    description="After /login returns mfa_required=true, submit the temp_token and TOTP code "
    "to complete authentication and receive full JWT tokens.",
)
def mfa_login(payload: MfaLoginRequest, request: Request, db: Session = Depends(get_db)):
    source_ip = _get_client_ip(request)
    user_agent = request.headers.get("user-agent", None)

    user_id = verify_mfa_temp_token(payload.temp_token)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid or expired MFA temp token")

    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    mfa = db.query(UserMfa).filter(UserMfa.user_id == user_id).first()

    # If MFA is enabled, verify TOTP code
    if mfa and mfa.enabled:
        totp = pyotp.TOTP(mfa.secret)
        code = payload.code.strip()
        if not totp.verify(code, valid_window=1):
            # Try backup codes
            if mfa.backup_codes and code in mfa.backup_codes:
                # Remove used backup code
                backup_codes_list = list(mfa.backup_codes)
                backup_codes_list.remove(code)
                mfa.backup_codes = backup_codes_list
                _audit_login(db, user.username, source_ip, user_agent, "backup_code_used", user_id=user.id, mfa_used=True)
            else:
                _audit_login(db, user.username, source_ip, user_agent, "invalid_mfa", user_id=user.id)
                raise HTTPException(status_code=400, detail="Invalid TOTP code or backup code")
        else:
            _audit_login(db, user.username, source_ip, user_agent, "success", user_id=user.id, mfa_used=True)
    else:
        raise HTTPException(status_code=400, detail="MFA not enabled for this user")

    # Consume the temp token
    _mfa_temp_tokens.pop(payload.temp_token, None)

    # Update last login and MFA last used
    mfa.last_used_at = datetime.now(UTC)
    user.last_login_at = datetime.now(UTC)
    db.commit()

    # Check for unknown LAN
    _check_unknown_lan(db, user.username, source_ip, user.id)

    access = create_access_token(user.id, user.role)
    refresh = create_refresh_token(user.id)
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}


@router.post(
    "/mfa/force-setup",
    summary="Force MFA setup (used when mfa_setup_required=true on login)",
    description="When login returns mfa_setup_required, the client calls this with the temp_token "
    "to initiate MFA setup. Returns TOTP secret, QR code, and backup codes. "
    "Then call /mfa/verify-setup to confirm.",
)
def mfa_force_setup(
    request: Request,
    db: Session = Depends(get_db),
):
    """This endpoint is a convenience: it uses a temp_token from the login flow
    to authenticate and set up MFA. The temp_token is passed in the Authorization header."""
    # Extract temp_token from Authorization header
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Temp token required")
    temp_token = auth_header[7:]
    user_id = verify_mfa_temp_token(temp_token)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid or expired MFA temp token")
    
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    # Generate TOTP secret
    totp = pyotp.TOTP(pyotp.random_base32())
    secret = totp.secret
    backup_codes = _generate_backup_codes()

    # Create or update MFA record
    mfa = db.query(UserMfa).filter(UserMfa.user_id == user.id).first()
    if mfa:
        mfa.secret = secret
        mfa.backup_codes = backup_codes
    else:
        mfa = UserMfa(
            user_id=user.id,
            secret=secret,
            backup_codes=backup_codes,
            enabled=False,
        )
        db.add(mfa)
    db.commit()
    db.refresh(mfa)

    # Generate QR code
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name="LogSOC"
    )
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_data_url = f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode()}"

    return {
        "secret": secret,
        "qr_code_url": qr_data_url,
        "backup_codes": backup_codes,
        "temp_token": temp_token,
        "user_id": user.id,
    }


class MfaForceVerifyRequest(BaseModel):
    temp_token: str
    code: str


@router.post(
    "/mfa/force-verify-setup",
    summary="Verify and enable MFA from forced setup flow",
    description="After /mfa/force-setup, verify the TOTP code to enable MFA "
    "and receive full JWT tokens.",
)
def mfa_force_verify_setup(
    payload: MfaForceVerifyRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    source_ip = _get_client_ip(request)
    user_agent = request.headers.get("user-agent", None)

    user_id = verify_mfa_temp_token(payload.temp_token)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid or expired MFA temp token")

    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    mfa = db.query(UserMfa).filter(UserMfa.user_id == user.id).first()
    if not mfa:
        raise HTTPException(status_code=400, detail="MFA not set up. Call /mfa/force-setup first.")

    totp = pyotp.TOTP(mfa.secret)
    code = payload.code.strip()
    if not totp.verify(code, valid_window=1):
        # Try backup codes
        if mfa.backup_codes and code in mfa.backup_codes:
            backup_codes_list = list(mfa.backup_codes)
            backup_codes_list.remove(code)
            mfa.backup_codes = backup_codes_list
        else:
            _audit_login(db, user.username, source_ip, user_agent, "invalid_mfa", user_id=user.id)
            raise HTTPException(status_code=400, detail="Invalid TOTP code or backup code")

    # Enable MFA
    mfa.enabled = True
    mfa.enabled_at = datetime.now(UTC)
    mfa.last_used_at = datetime.now(UTC)
    user.mfa_setup_required = False
    user.last_login_at = datetime.now(UTC)

    # Consume temp token
    _mfa_temp_tokens.pop(payload.temp_token, None)
    db.commit()

    _audit_login(db, user.username, source_ip, user_agent, "success", user_id=user.id, mfa_used=True)

    # Check for unknown LAN
    _check_unknown_lan(db, user.username, source_ip, user.id)

    # Return full JWT tokens
    access = create_access_token(user.id, user.role)
    refresh = create_refresh_token(user.id)
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}


# ══════════════════════════════════════════════════════════════════════════
# MFA Policy (admin)
# ══════════════════════════════════════════════════════════════════════════

@router.get(
    "/admin/mfa/policy",
    summary="Get MFA global policy",
    description="Admin-only. Returns the current MFA policy configuration.",
)
def mfa_policy_get(current_user: User = Depends(require_role('admin', 'rssi'))):
    policy = _get_mfa_policy()
    return policy


class MfaPolicyUpdate(BaseModel):
    required: Optional[bool] = None
    enforce_for_roles: Optional[list[str]] = None


@router.put(
    "/admin/mfa/policy",
    summary="Update MFA global policy",
    description="Admin-only. Updates the MFA policy in config.yaml.",
)
def mfa_policy_update(
    payload: MfaPolicyUpdate,
    current_user: User = Depends(require_role('superadmin', 'admin')),
):
    import yaml
    from pathlib import Path

    # Find config file
    config_paths = [
        Path("/app/config.yaml"),
        Path("/opt/logsoc-web/config.yaml"),
        Path("./config.yaml"),
    ]
    config_path = None
    for p in config_paths:
        if p.exists() and p.is_file():
            config_path = p
            break

    if not config_path:
        raise HTTPException(status_code=500, detail="No config.yaml found")

    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    if "mfa" not in config:
        config["mfa"] = {}

    if payload.required is not None:
        config["mfa"]["required"] = payload.required
    if payload.enforce_for_roles is not None:
        config["mfa"]["enforce_for_roles"] = payload.enforce_for_roles

    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False)

    # Also update the in-memory config
    from app.config_loader import CFG
    CFG["mfa"] = config["mfa"]

    return {"message": "MFA policy updated", "mfa": config["mfa"]}


@router.put(
    "/admin/mfa/enforce/{user_id}",
    summary="Force MFA setup for a user",
    description="Admin-only. Sets the mfa_setup_required flag for a user, "
    "forcing them to set up MFA on next login.",
)
def mfa_enforce_user(
    user_id: int,
    current_user: User = Depends(require_role('superadmin', 'admin')),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.mfa_setup_required = True
    db.commit()
    return {"message": f"MFA setup required for user {user.username}", "mfa_setup_required": True}


@router.post(
    "/admin/mfa/reset/{user_id}",
    summary="Admin: reset MFA for a user (disable and clear secrets)",
)
def admin_reset_mfa(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ("superadmin", "admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # Delete MFA record
    db.query(UserMfa).filter(UserMfa.user_id == user_id).delete()
    user.mfa_setup_required = False
    db.commit()
    return {"status": "ok", "message": f"MFA reset for user {user.username}"}


@router.delete(
    "/admin/mfa/enforce/{user_id}",
    summary="Remove MFA setup requirement for a user",
    description="Admin-only. Clears the mfa_setup_required flag for a user.",
)
def mfa_unenforce_user(
    user_id: int,
    current_user: User = Depends(require_role('superadmin', 'admin')),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.mfa_setup_required = False
    db.commit()
    return {"message": f"MFA setup requirement removed for user {user.username}", "mfa_setup_required": False}


# ══════════════════════════════════════════════════════════════════════════
# Login Audit (admin)
# ══════════════════════════════════════════════════════════════════════════

@router.get(
    "/admin/login-audit",
    summary="List login audit entries",
    description="Admin-only. Returns paginated login audit trail with filters.",
)
def login_audit_list(
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    status: Optional[str] = None,
    source_ip: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    current_user: User = Depends(require_role('superadmin', 'admin', 'rssi', 'auditor')),
    db: Session = Depends(get_db),
):
    query = db.query(LoginAudit)

    if user_id is not None:
        query = query.filter(LoginAudit.user_id == user_id)
    if username:
        query = query.filter(LoginAudit.username.ilike(f"%{username}%"))
    if status:
        query = query.filter(LoginAudit.status == status)
    if source_ip:
        query = query.filter(LoginAudit.source_ip == source_ip)
    if date_from:
        try:
            from datetime import datetime as dt
            df = dt.fromisoformat(date_from)
            query = query.filter(LoginAudit.timestamp >= df)
        except ValueError:
            pass
    if date_to:
        try:
            from datetime import datetime as dt
            dt_to = dt.fromisoformat(date_to)
            query = query.filter(LoginAudit.timestamp <= dt_to)
        except ValueError:
            pass

    total = query.count()
    entries = query.order_by(LoginAudit.timestamp.desc()).offset(offset).limit(limit).all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": [
            {
                "id": e.id,
                "user_id": e.user_id,
                "username": e.username,
                "source_ip": e.source_ip,
                "user_agent": e.user_agent,
                "status": e.status,
                "mfa_used": e.mfa_used,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            }
            for e in entries
        ],
    }


@router.get(
    "/admin/login-audit/stats",
    summary="Login audit statistics",
    description="Admin-only. Returns login audit stats: total, by status, top IPs, etc.",
)
def login_audit_stats(
    current_user: User = Depends(require_role('superadmin', 'admin', 'rssi', 'auditor')),
    db: Session = Depends(get_db),
):
    from sqlalchemy import func

    # Total logins
    total = db.query(func.count(LoginAudit.id)).scalar() or 0

    # Successful logins
    success_count = db.query(func.count(LoginAudit.id)).filter(
        LoginAudit.status == "success"
    ).scalar() or 0

    # Failed attempts (invalid_password + invalid_mfa + unknown_user + account_locked)
    failed_count = db.query(func.count(LoginAudit.id)).filter(
        LoginAudit.status.in_(["invalid_password", "invalid_mfa", "unknown_user", "account_locked"])
    ).scalar() or 0

    # MFA used
    mfa_count = db.query(func.count(LoginAudit.id)).filter(
        LoginAudit.mfa_used == True
    ).scalar() or 0

    # Unknown LAN
    unknown_lan_count = db.query(func.count(LoginAudit.id)).filter(
        LoginAudit.status == "unknown_lan"
    ).scalar() or 0

    # Unique IPs
    unique_ips = db.query(func.count(func.distinct(LoginAudit.source_ip))).scalar() or 0

    # Top IPs
    top_ips_rows = db.query(
        LoginAudit.source_ip,
        func.count(LoginAudit.id).label("count")
    ).group_by(
        LoginAudit.source_ip
    ).order_by(
        func.count(LoginAudit.id).desc()
    ).limit(10).all()

    # Logins per day (last 30 days)
    thirty_days_ago = datetime.now(UTC) - timedelta(days=30)
    logins_per_day = db.query(
        func.date(LoginAudit.timestamp).label("date"),
        func.count(LoginAudit.id).label("count")
    ).filter(
        LoginAudit.timestamp >= thirty_days_ago
    ).group_by(
        func.date(LoginAudit.timestamp)
    ).order_by(
        func.date(LoginAudit.timestamp)
    ).all()

    # By status
    by_status_rows = db.query(
        LoginAudit.status,
        func.count(LoginAudit.id).label("count")
    ).group_by(LoginAudit.status).all()

    return {
        "total_logins": total,
        "successful_logins": success_count,
        "failed_attempts": failed_count,
        "mfa_used_count": mfa_count,
        "unknown_lan_count": unknown_lan_count,
        "unique_ips": unique_ips,
        "top_ips": [{"ip": ip, "count": count} for ip, count in top_ips_rows],
        "logins_per_day": [{"date": str(d), "count": c} for d, c in logins_per_day],
        "by_status": [{"status": s, "count": c} for s, c in by_status_rows],
    }


# ══════════════════════════════════════════════════════════════════════════
# SSO endpoints (Phase 1.3)
# ══════════════════════════════════════════════════════════════════════════

class SsoConfigUpdate(BaseModel):
    provider: str  # e.g. "saml", "oidc", "google", "github"
    name: str  # Human-readable name
    config: dict  # Provider-specific config (client_id, client_secret, etc.)
    attribute_mapping: Optional[dict] = None  # Map SSO attributes to local user fields
    is_active: bool = True

@router.get(
    "/sso/providers",
    summary="List active SSO providers",
    description="Public endpoint for the login page. Returns all active SSO configurations.",
)
def sso_providers(db: Session = Depends(get_db)):
    configs = db.query(SsoConfig).filter(SsoConfig.is_active == True).all()
    return [
        {
            "id": c.id,
            "provider": c.provider,
            "name": c.name,
        }
        for c in configs
    ]


@router.get(
    "/sso/{provider}/login",
    summary="Initiate SSO login",
    description="Redirect to SSO provider for authentication. "
    "TODO: implement with python3-saml or authlib.",
    responses={501: {"description": "Not implemented — pending SSO library integration"}},
)
def sso_login(provider: str, db: Session = Depends(get_db)):
    # Verify the provider exists and is active
    config = db.query(SsoConfig).filter(
        SsoConfig.provider == provider,
        SsoConfig.is_active == True,
    ).first()
    if not config:
        raise HTTPException(status_code=404, detail=f"SSO provider '{provider}' not found or inactive")

    # TODO: implement with python3-saml or authlib
    # This will redirect to the SSO provider's login page and handle the callback.
    # The redirect URL and SAML/OIDC flow depend on the provider configuration
    # stored in sso_config.config.
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="SSO login redirect not yet implemented. Install python3-saml or authlib and configure the callback endpoint.",
    )


@router.put(
    "/admin/sso/{config_id}",
    summary="Create or update SSO configuration",
    description="Admin-only endpoint to create (config_id=0) or update an SSO provider configuration.",
)
def sso_config_update(
    config_id: int,
    payload: SsoConfigUpdate,
    current_user: User = Depends(require_role('superadmin', 'admin')),
    db: Session = Depends(get_db),
):
    if config_id == 0:
        # Create new config
        config = SsoConfig(
            provider=payload.provider,
            name=payload.name,
            config=payload.config,
            attribute_mapping=payload.attribute_mapping,
            is_active=payload.is_active,
        )
        db.add(config)
        db.commit()
        db.refresh(config)
        return {
            "id": config.id,
            "provider": config.provider,
            "name": config.name,
            "is_active": config.is_active,
            "created_at": config.created_at.isoformat() if config.created_at else None,
        }
    else:
        # Update existing config
        config = db.query(SsoConfig).filter(SsoConfig.id == config_id).first()
        if not config:
            raise HTTPException(status_code=404, detail="SSO configuration not found")

        config.provider = payload.provider
        config.name = payload.name
        config.config = payload.config
        config.attribute_mapping = payload.attribute_mapping
        config.is_active = payload.is_active
        db.commit()
        db.refresh(config)
        return {
            "id": config.id,
            "provider": config.provider,
            "name": config.name,
            "is_active": config.is_active,
            "updated_at": config.updated_at.isoformat() if config.updated_at else None,
        }