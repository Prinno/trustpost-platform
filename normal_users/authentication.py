import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from django.conf import settings
from django.utils.translation import gettext_lazy as _
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework import exceptions

from .models import NormalUser


class AuthenticatedNormalUser:
    def __init__(self, user: NormalUser):
        self._normal_user = user

    @property
    def is_authenticated(self):
        return True

    @property
    def normal_user(self) -> NormalUser:
        return self._normal_user

    def __str__(self):
        return f"AuthenticatedNormalUser({self._normal_user})"


def _jwt_secret() -> str:
    return getattr(settings, "NORMAL_USER_JWT_SECRET", settings.SECRET_KEY)


def create_jwt(payload: dict, minutes: int) -> str:
    now = datetime.now(tz=timezone.utc)
    exp = now + timedelta(minutes=minutes)
    body = {"iat": int(now.timestamp()), "exp": int(exp.timestamp()), **payload}
    return jwt.encode(body, _jwt_secret(), algorithm="HS256")


def decode_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, _jwt_secret(), algorithms=["HS256"])
    except jwt.ExpiredSignatureError as e:
        raise exceptions.AuthenticationFailed(_("Token expired")) from e
    except jwt.InvalidTokenError as e:
        raise exceptions.AuthenticationFailed(_("Invalid token")) from e


class NormalUserJWTAuthentication(BaseAuthentication):
    keyword = b"Bearer"

    def authenticate(self, request) -> Optional[Tuple[AuthenticatedNormalUser, str]]:
        auth = get_authorization_header(request).split()
        if not auth:
            return None
        if auth[0].lower() != self.keyword.lower():
            return None
        if len(auth) == 1:
            raise exceptions.AuthenticationFailed(_("Invalid Authorization header."))
        if len(auth) > 2:
            raise exceptions.AuthenticationFailed(_("Invalid Authorization header."))

        token = auth[1].decode("utf-8")
        data = decode_jwt(token)
        if data.get("sub") != "normal_user_access":
            raise exceptions.AuthenticationFailed(_("Invalid token subject"))
        uid = data.get("uid")
        try:
            user = NormalUser.objects.get(id=uid, is_active=True)
        except NormalUser.DoesNotExist:
            raise exceptions.AuthenticationFailed(_("User not found or inactive"))
        return AuthenticatedNormalUser(user), token
