from django.db import models
from django.contrib.auth import get_user_model


User = get_user_model()


class AdminAccount(models.Model):
    ROLE_ADMIN = "admin"
    ROLE_SUPERADMIN = "superadmin"
    ROLE_CHOICES = (
        (ROLE_ADMIN, "Admin"),
        (ROLE_SUPERADMIN, "Super Admin"),
    )

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="admin_account")
    role = models.CharField(max_length=16, choices=ROLE_CHOICES, default=ROLE_ADMIN)
    is_enabled = models.BooleanField(default=True)
    permissions = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"AdminAccount#{self.pk} {self.user_id} ({self.role}) enabled={self.is_enabled}"


class GlobalSetting(models.Model):
    """
    Simple key/value config for feature toggles and platform settings.
    Example keys: feature_posting_enabled, moderation_required, etc.
    """
    key = models.CharField(max_length=64, unique=True)
    value = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"GlobalSetting({self.key})"
