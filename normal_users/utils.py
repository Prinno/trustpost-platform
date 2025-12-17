import random
import string
from datetime import datetime, timedelta, timezone
from django.conf import settings
from django.core.mail import send_mail


def generate_token(length: int = 48) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def generate_otp(length: int = 6) -> str:
    return "".join(random.choice(string.digits) for _ in range(length))


def now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


def email_send(subject: str, message: str, recipient: str):
    from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@example.com")
    send_mail(subject, message, from_email, [recipient], fail_silently=True)
