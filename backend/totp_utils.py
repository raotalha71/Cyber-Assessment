import pyotp
import qrcode
import base64
from io import BytesIO

def generate_totp_secret():
    return pyotp.random_base32()

def generate_qr_code(email: str, secret: str):
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name="Cyber Risk Assessment System"
    )

    qr = qrcode.make(uri)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")

    return base64.b64encode(buffer.getvalue()).decode()

def verify_totp(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code)
