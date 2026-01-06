# email_sender.py
import os
import smtplib
from email.mime.text import MIMEText

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

def send_email_otp(to_email: str, otp: str):
    """
    Sends a simple OTP email using Gmail SMTP + App Password.
    """
    if not EMAIL_USER or not EMAIL_PASS:
        print("❌ EMAIL_USER or EMAIL_PASS not set in .env")
        return

    body = f"Your Cyber Risk System OTP code is: {otp}\n\nThis code is valid for 5 minutes."
    msg = MIMEText(body)
    msg["Subject"] = "Your Cyber Risk System OTP Code"
    msg["From"] = EMAIL_USER
    msg["To"] = to_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        print(f"✅ OTP email sent to {to_email}")
    except Exception as e:
        print(f"❌ Failed to send OTP email to {to_email}: {e}")
