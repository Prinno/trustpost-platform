from rest_framework.permissions import BasePermission

from .models import NormalUser


class IsNormalUser(BasePermission):
    def has_permission(self, request, view):
        user = getattr(request, "user", None)
        if not (bool(user) and getattr(user, "is_authenticated", False) and hasattr(user, "normal_user")):
            return False
        nu = getattr(user, "normal_user", None)
        # Only fully active accounts (including advertisers approved by admin) may access protected endpoints
        return bool(nu) and getattr(nu, "status", NormalUser.STATUS_ACTIVE) == NormalUser.STATUS_ACTIVE
