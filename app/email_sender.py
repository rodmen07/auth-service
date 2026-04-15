import logging
import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)

_APP_NAME = os.getenv("APP_NAME", "Portfolio")


def _smtp_config() -> tuple[str, int, str, str, str] | None:
    """Return (host, port, user, password, from_addr) or None if not configured."""
    host = os.getenv("SMTP_HOST", "").strip()
    user = os.getenv("SMTP_USER", "").strip()
    password = os.getenv("SMTP_PASSWORD", "").strip()
    if not all([host, user, password]):
        return None
    port = int(os.getenv("SMTP_PORT", "587"))
    from_addr = os.getenv("SMTP_FROM", user).strip()
    return host, port, user, password, from_addr


def _send_email(to_email: str, subject: str, body: str) -> None:
    cfg = _smtp_config()
    if cfg is None:
        logger.info("SMTP not configured — email for %s: subject=%r", to_email, subject)
        return
    host, port, user, password, from_addr = cfg
    msg = MIMEText(body, "plain")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_email
    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(host, port, timeout=10) as server:
            server.ehlo()
            server.starttls(context=context)
            server.login(user, password)
            server.sendmail(from_addr, [to_email], msg.as_string())
        logger.info("Email sent to %s: %r", to_email, subject)
    except Exception as exc:
        logger.error("Failed to send email to %s: %s", to_email, exc)


async def send_password_reset_email(to_email: str, reset_url: str) -> None:
    """Send a password reset email. Falls back to logging the URL if SMTP is not configured."""
    body = f"""Hello,

You requested a password reset for your {_APP_NAME} account.

Click the link below to set a new password (valid for 1 hour):

{reset_url}

If you did not request this, you can safely ignore this email.

— {_APP_NAME}
"""
    _send_email(to_email, f"Reset your {_APP_NAME} password", body)
    if _smtp_config() is None:
        logger.info("Reset URL for %s: %s", to_email, reset_url)


async def send_invite_email(to_email: str, invite_url: str) -> None:
    """Send a client portal invite email."""
    body = f"""Hello,

You've been invited to access the {_APP_NAME} client portal.

Click the link below to create your account (valid for 72 hours):

{invite_url}

— {_APP_NAME}
"""
    _send_email(to_email, f"You're invited to {_APP_NAME}", body)
    if _smtp_config() is None:
        logger.info("Invite URL for %s: %s", to_email, invite_url)
