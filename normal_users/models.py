from django.db import models
from django.utils import timezone


class NormalUser(models.Model):
    email = models.EmailField(unique=True, null=True, blank=True)
    phone = models.CharField(max_length=20, unique=True, null=True, blank=True)
    password = models.CharField(max_length=255)
    is_active = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)
    is_phone_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        ident = self.email or self.phone or f"NormalUser#{self.pk}"
        return ident


class VerificationToken(models.Model):
    EMAIL_VERIFY = "email_verify"
    PASSWORD_RESET = "password_reset"
    TOKEN_TYPES = (
        (EMAIL_VERIFY, "Email Verification"),
        (PASSWORD_RESET, "Password Reset"),
    )

    user = models.ForeignKey(NormalUser, on_delete=models.CASCADE, related_name="verification_tokens")
    token = models.CharField(max_length=128, unique=True)
    type = models.CharField(max_length=32, choices=TOKEN_TYPES)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self) -> bool:
        return (not self.used) and (self.expires_at > timezone.now())


class PhoneOTP(models.Model):
    user = models.ForeignKey(NormalUser, on_delete=models.CASCADE, related_name="phone_otps")
    code = models.CharField(max_length=6)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    attempt_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self) -> bool:
        return (not self.used) and (self.expires_at > timezone.now())


class RefreshToken(models.Model):
    user = models.ForeignKey(NormalUser, on_delete=models.CASCADE, related_name="refresh_tokens")
    token = models.CharField(max_length=512, unique=True)
    revoked = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def is_active(self) -> bool:
        return (not self.revoked) and (self.expires_at > timezone.now())
