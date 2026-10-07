import hashlib
import secrets
import smtplib
import time
from datetime import datetime, timedelta
from email.message import EmailMessage

from config import (
    EMAIL_OTP_ENABLED,
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USERNAME,
    SMTP_APP_PASSWORD,
    SMTP_FROM_EMAIL,
    SMS_OTP_ENABLED,
    TWILIO_ACCOUNT_SID,
    TWILIO_AUTH_TOKEN,
    TWILIO_FROM_NUMBER,
    OTP_LENGTH,
    OTP_EXPIRY_SECONDS,
    OTP_MAX_ATTEMPTS,
    OTP_RESEND_COOLDOWN_SECONDS,
)
from database import (
    save_otp,
    get_active_otp,
    increment_otp_attempts,
    mark_otp_used,
)


def _hash_otp(otp):
    return hashlib.sha256(
        otp.encode("utf-8")
    ).hexdigest()


def _generate_otp():
    lower = 10 ** (OTP_LENGTH - 1)
    upper = (10 ** OTP_LENGTH) - 1

    return str(
        secrets.randbelow(upper - lower + 1) + lower
    )


def _send_email_otp(destination, otp, purpose):
    if not EMAIL_OTP_ENABLED:
        return False, "DEMO"

    if not SMTP_USERNAME or not SMTP_APP_PASSWORD:
        return False, "DEMO"

    message = EmailMessage()

    message["Subject"] = "Secure File Vault OTP"
    message["From"] = SMTP_FROM_EMAIL or SMTP_USERNAME
    message["To"] = destination

    message.set_content(
        "Secure File Vault\n\n"
        f"Your OTP for {purpose.replace('_', ' ')} is: {otp}\n\n"
        f"This OTP expires in {OTP_EXPIRY_SECONDS // 60} minutes.\n"
        "Do not share this OTP with anyone."
    )

    with smtplib.SMTP(
        SMTP_HOST,
        SMTP_PORT,
        timeout=20
    ) as server:

        server.starttls()

        server.login(
            SMTP_USERNAME,
            SMTP_APP_PASSWORD
        )

        server.send_message(message)

    return True, "EMAIL"


def _send_sms_otp(destination, otp, purpose):
    if not SMS_OTP_ENABLED:
        return False, "DEMO"

    if not all([
        TWILIO_ACCOUNT_SID,
        TWILIO_AUTH_TOKEN,
        TWILIO_FROM_NUMBER
    ]):
        return False, "DEMO"

    try:
        from twilio.rest import Client
    except ImportError as error:
        raise RuntimeError(
            "SMS OTP requires the 'twilio' package. "
            "Run: pip install twilio"
        ) from error

    client = Client(
        TWILIO_ACCOUNT_SID,
        TWILIO_AUTH_TOKEN
    )

    client.messages.create(
        body=(
            f"Secure File Vault OTP: {otp}\n"
            f"Purpose: {purpose.replace('_', ' ')}\n"
            f"Expires in {OTP_EXPIRY_SECONDS // 60} minutes."
        ),
        from_=TWILIO_FROM_NUMBER,
        to=destination
    )

    return True, "SMS"


def send_otp(
    user_id,
    method,
    destination,
    purpose
):
    now = datetime.now()

    active = get_active_otp(
        user_id,
        purpose,
        method
    )

    if active:
        try:
            created = datetime.fromisoformat(
                active["created_at"]
            )

            elapsed = (
                now - created
            ).total_seconds()

            if elapsed < OTP_RESEND_COOLDOWN_SECONDS:
                remaining = int(
                    OTP_RESEND_COOLDOWN_SECONDS - elapsed
                )

                return {
                    "success": False,
                    "message": (
                        f"Please wait {remaining} seconds "
                        "before requesting another OTP."
                    ),
                    "demo_otp": None
                }

        except Exception:
            pass

    otp = _generate_otp()

    expires_at = now + timedelta(
        seconds=OTP_EXPIRY_SECONDS
    )

    sent = False
    delivery = "DEMO"

    if method == "email":
        sent, delivery = _send_email_otp(
            destination,
            otp,
            purpose
        )

    elif method == "sms":
        sent, delivery = _send_sms_otp(
            destination,
            otp,
            purpose
        )

    else:
        return {
            "success": False,
            "message": "Invalid OTP method.",
            "demo_otp": None
        }

    save_otp(
        user_id,
        purpose,
        method,
        destination,
        _hash_otp(otp),
        now.isoformat(timespec="seconds"),
        expires_at.isoformat(timespec="seconds")
    )

    if delivery == "DEMO":
        return {
            "success": True,
            "message": (
                "OTP generated in DEMO mode. "
                "Configure email/SMS settings in config.py "
                "for real delivery."
            ),
            "demo_otp": otp
        }

    return {
        "success": True,
        "message": (
            f"OTP sent successfully to your {method}."
        ),
        "demo_otp": None
    }


def verify_otp(
    user_id,
    purpose,
    method,
    entered_otp
):
    record = get_active_otp(
        user_id,
        purpose,
        method
    )

    if not record:
        return False, "No active OTP found."

    if record["used"]:
        return False, "This OTP has already been used."

    if record["attempts"] >= OTP_MAX_ATTEMPTS:
        return False, "Maximum OTP attempts exceeded."

    try:
        expires_at = datetime.fromisoformat(
            record["expires_at"]
        )

        if datetime.now() > expires_at:
            return False, "OTP has expired."

    except Exception:
        return False, "Invalid OTP expiry information."

    increment_otp_attempts(record["id"])

    entered_hash = _hash_otp(
        entered_otp.strip()
    )

    if not secrets.compare_digest(
        entered_hash,
        record["otp_hash"]
    ):
        remaining = max(
            0,
            OTP_MAX_ATTEMPTS - record["attempts"] - 1
        )

        return False, (
            f"Incorrect OTP. Attempts remaining: {remaining}"
        )

    mark_otp_used(record["id"])

    return True, "OTP verified successfully."
