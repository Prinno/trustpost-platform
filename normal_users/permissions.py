from rest_framework.permissions import BasePermission


class IsNormalUser(BasePermission):
    def has_permission(self, request, view):
        user = getattr(request, "user", None)
        return bool(user) and getattr(user, "is_authenticated", False) and hasattr(user, "normal_user")
