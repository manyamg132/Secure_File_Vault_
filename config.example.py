"""
Secure File Vault V2 configuration.

For real email/SMS OTP:
1. Fill the SMTP settings below for email.
2. Fill the Twilio settings below for SMS.
3. If a provider is not configured, the application uses DEMO OTP mode
   and shows the OTP in the application. This keeps local testing possible.
"""

# ---------------- EMAIL OTP ----------------

EMAIL_OTP_ENABLED = True

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "your Gmail address"       # Example: your Gmail address
SMTP_APP_PASSWORD = "your_app_password"    # Gmail App Password, not your normal password
SMTP_FROM_EMAIL = "Gmail address"          # Usually same as SMTP_USERNAME


# ---------------- SMS OTP ----------------

SMS_OTP_ENABLED = True

TWILIO_ACCOUNT_SID = "account SID"            #your Twilio account SID
TWILIO_AUTH_TOKEN = "authentication token"    #your Twilio account authentication token
TWILIO_FROM_NUMBER = "Twilio From number"     #Twilio From number


# ---------------- OTP SETTINGS ----------------

OTP_LENGTH = 6
OTP_EXPIRY_SECONDS = 300       # 5 minutes
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_COOLDOWN_SECONDS = 60


# ---------------- DATABASE ----------------

DATABASE_FILE = "secure_vault.db"
