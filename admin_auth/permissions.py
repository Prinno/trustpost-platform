from rest_framework.permissions import BasePermission
from django.contrib.auth import get_user_model
from .models import AdminAccount


User = get_user_model()


class IsAdminEnabled(BasePermission):
    """Allow only enabled Admins or Super Admins."""

    def has_permission(self, request, view):
        user = getattr(request, "user", None)
        if not user or not getattr(user, "is_authenticated", False):
            return False
        if not (getattr(user, "is_staff", False) or getattr(user, "is_superuser", False)):
            return False
        acc = getattr(user, "admin_account", None)
        if acc is None:
            # If no AdminAccount row, fall back to is_staff/is_superuser
            return bool(getattr(user, "is_staff", False) or getattr(user, "is_superuser", False))
        return acc.is_enabled


class IsSuperAdmin(BasePermission):
    """Allow only Super Admins (with enabled account if present)."""

    def has_permission(self, request, view):
        user = getattr(request, "user", None)
        if not user or not getattr(user, "is_authenticated", False):
            return False
        if not getattr(user, "is_superuser", False):
            return False
        acc = getattr(user, "admin_account", None)
        if acc is None:
            return True
        return acc.is_enabled and acc.role == AdminAccount.ROLE_SUPERADMIN
