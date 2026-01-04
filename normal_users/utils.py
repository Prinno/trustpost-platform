import random
import string
from datetime import datetime, timedelta, timezone
from django.conf import settings
from django.core.mail import send_mail


def normalize_media_url(url: str | None) -> str | None:
    """
    Normalize any media URL to a relative path (IP/domain agnostic).

    Rules:
    - Strip protocol + host from absolute URLs like
      "http://192.168.1.10:8000/media/avatars/x.jpg" → "/media/avatars/x.jpg"
    - Ensure leading "/" and MEDIA_URL prefix when path is missing
    - Leave empty/None as-is
    """
    if not url:
        return url
    try:
        from urllib.parse import urlparse
        from django.conf import settings

        parsed = urlparse(url)
        # If scheme/netloc present, keep only path
        path = parsed.path if parsed.scheme or parsed.netloc else url
        if not path:
            return None
        # Ensure it starts with '/'
        if not path.startswith('/'):
            path = '/' + path
        media_prefix = getattr(settings, 'MEDIA_URL', '/media/')
        # Ensure MEDIA_URL prefix
        if not path.startswith(media_prefix):
            # If already contains 'media/' somewhere, align to '/media/...'
            if 'media/' in path:
                idx = path.find('media/')
                path = '/' + path[idx:]
            else:
                # Prepend MEDIA_URL to provided relative file segment
                # e.g. '/avatars/x.jpg' → '/media/avatars/x.jpg'
                seg = path.lstrip('/')
                path = media_prefix.rstrip('/') + '/' + seg
        return path
    except Exception:
        # Fail-safe: return the original string
        return url


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
