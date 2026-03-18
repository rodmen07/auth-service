import logging
import os
import smtplib
import ssl
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)


async def send_password_reset_email(to_email: str, reset_url: str) -> None:
    """Send a password reset email. Falls back to logging the URL if SMTP is not configured."""
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "").strip()
    smtp_password = os.getenv("SMTP_PASSWORD", "").strip()
    smtp_from = os.getenv("SMTP_FROM", smtp_user).strip()

    if not all([smtp_host, smtp_user, smtp_password]):
        logger.info("SMTP not configured — password reset URL for %s: %s", to_email, reset_url)
        return

    body = f"""Hello,

You requested a password reset for your InfraPortal account.

Click the link below to set a new password (valid for 1 hour):

{reset_url}

If you did not request this, you can safely ignore this email.

— InfraPortal
"""
    msg = MIMEText(body, "plain")
    msg["Subject"] = "Reset your InfraPortal password"
    msg["From"] = smtp_from
    msg["To"] = to_email

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.ehlo()
            server.starttls(context=context)
            server.login(smtp_user, smtp_password)
            server.sendmail(smtp_from, [to_email], msg.as_string())
        logger.info("Password reset email sent to %s", to_email)
    except Exception as exc:
        logger.error("Failed to send reset email to %s: %s", to_email, exc)
        logger.info("Reset URL for %s: %s", to_email, reset_url)
