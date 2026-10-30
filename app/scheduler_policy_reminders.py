"""app/scheduler_policy_reminders.py — Ticket #24

Daily scheduled task (09:00 Paris time / 07:00 UTC) that:
1. Finds all published policies with published_at >= 7 days ago
2. For each policy, finds recipients who haven't acknowledged the current version
3. Inserts/updates policy_reminders rows (idempotent per day per user per policy)
4. Sends dashboard notifications (and email if configured)

This module is designed to be called from the FastAPI lifespan or from
an external scheduler. It uses the same database session pattern as the
rest of the app.

Integration: called from app/main.py lifespan or from a separate
sidecar process similar to retention_entrypoint.py.
"""

import datetime
import logging
from zoneinfo import ZoneInfo

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import User, SecurityPolicy, PolicyAcknowledgment, PolicyReminder

logger = logging.getLogger("logsoc.policy_reminders")

PARIS_TZ = ZoneInfo("Europe/Paris")


def run_policy_reminder_job() -> dict:
    """Execute the J+7 policy reminder job.

    Returns a summary dict with counts for logging/monitoring.
    """
    db: Session = SessionLocal()
    summary = {
        "policies_checked": 0,
        "reminders_sent": 0,
        "reminders_skipped_idempotent": 0,
        "errors": 0,
    }

    try:
        now = datetime.datetime.now(datetime.timezone.utc)
        seven_days_ago = now - datetime.timedelta(days=7)
        today_date = now.date()

        # Find all published policies published >= 7 days ago
        policies = db.query(SecurityPolicy).filter(
            SecurityPolicy.status == 'published',
            SecurityPolicy.published_at != None,  # noqa: E711
            SecurityPolicy.published_at <= seven_days_ago,
        ).all()

        summary["policies_checked"] = len(policies)

        for policy in policies:
            version = policy.version

            # Determine recipient user IDs
            if policy.recipients and isinstance(policy.recipients, list):
                recipient_ids = policy.recipients
            else:
                # All active users
                recipient_ids = [
                    u.id for u in db.query(User).filter(User.is_active == True).all()  # noqa: E712
                ]

            if not recipient_ids:
                continue

            # Find users who already acknowledged this version
            acked_user_ids = set(
                r[0] for r in db.query(PolicyAcknowledgment.user_id).filter(
                    PolicyAcknowledgment.policy_id == policy.id,
                    PolicyAcknowledgment.version == version,
                ).all()
            )

            # For each recipient who hasn't acknowledged, send a reminder
            for uid in recipient_ids:
                if uid in acked_user_ids:
                    continue  # Already acknowledged, skip

                # Idempotency: check if we already sent a reminder today
                # sent_date is a GENERATED ALWAYS AS (DATE(sent_at)) STORED column
                existing = db.query(PolicyReminder).filter(
                    PolicyReminder.policy_id == policy.id,
                    PolicyReminder.user_id == uid,
                    PolicyReminder.sent_date == today_date,
                ).first()

                if existing:
                    summary["reminders_skipped_idempotent"] += 1
                    continue

                # Check if there's a previous reminder for this policy+user
                # to increment the reminder_count
                prev_reminder = db.query(PolicyReminder).filter(
                    PolicyReminder.policy_id == policy.id,
                    PolicyReminder.user_id == uid,
                ).order_by(PolicyReminder.sent_at.desc()).first()

                new_count = (prev_reminder.reminder_count + 1) if prev_reminder else 1

                # Determine delivery channel
                # Default to 'dashboard'; could be 'email' or 'both' if configured
                # For now, default is 'dashboard'
                channel = 'dashboard'

                reminder = PolicyReminder(
                    policy_id=policy.id,
                    user_id=uid,
                    version=version,
                    reminder_count=new_count,
                    delivery_channel=channel,
                )
                db.add(reminder)
                summary["reminders_sent"] += 1

                # Log the reminder event
                logger.info(
                    "Reminder #%d: policy_id=%d user_id=%d version=%s channel=%s",
                    new_count, policy.id, uid, version, channel,
                )

        db.commit()

    except Exception as e:
        db.rollback()
        summary["errors"] += 1
        logger.exception("Policy reminder job failed: %s", e)
    finally:
        db.close()

    logger.info(
        "Policy reminder job complete: checked=%d sent=%d skipped=%d errors=%d",
        summary["policies_checked"],
        summary["reminders_sent"],
        summary["reminders_skipped_idempotent"],
        summary["errors"],
    )
    return summary


def run_policy_reminder_standalone():
    """Standalone entry point for the policy reminder scheduler.

    Runs the job once and exits. Intended to be called from a cron
    sidecar or external scheduler at 09:00 Paris time.

    Usage:
        python -m app.scheduler_policy_reminders
    """
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s.%(msecs)03d [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )
    result = run_policy_reminder_job()
    if result["errors"] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    run_policy_reminder_standalone()