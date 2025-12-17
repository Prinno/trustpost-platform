from django.contrib import admin
from .models import NormalUser, VerificationToken, PhoneOTP, RefreshToken


@admin.register(NormalUser)
class NormalUserAdmin(admin.ModelAdmin):
    list_display = ("id", "email", "phone", "is_active", "is_email_verified", "is_phone_verified", "created_at")
    search_fields = ("email", "phone")
    list_filter = ("is_active", "is_email_verified", "is_phone_verified")


@admin.register(VerificationToken)
class VerificationTokenAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "type", "expires_at", "used", "created_at")
    list_filter = ("type", "used")
    search_fields = ("token", "user__email", "user__phone")


@admin.register(PhoneOTP)
class PhoneOTPAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "code", "expires_at", "used", "attempt_count", "created_at")
    list_filter = ("used",)
    search_fields = ("user__email", "user__phone")


@admin.register(RefreshToken)
class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "revoked", "expires_at", "created_at")
    list_filter = ("revoked",)
    search_fields = ("user__email", "user__phone")
