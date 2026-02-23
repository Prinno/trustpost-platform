from django.contrib import admin

from .models import NormalUser, VerificationToken, PhoneOTP, RefreshToken
from .utils import email_send


@admin.register(NormalUser)
class NormalUserAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "email",
        "phone",
        "account_type",
        "status",
        "is_active",
        "is_email_verified",
        "is_phone_verified",
        "created_at",
    )
    search_fields = ("email", "phone", "username", "organization_name")
    list_filter = ("account_type", "status", "is_active", "is_email_verified", "is_phone_verified")

    actions = ["approve_advertisers", "reject_advertisers"]

    def approve_advertisers(self, request, queryset):
        advertisers = queryset.filter(
            account_type=NormalUser.ACCOUNT_TYPE_ADVERTISER,
            status=NormalUser.STATUS_PENDING,
        )
        for user in advertisers:
            user.status = NormalUser.STATUS_ACTIVE
            user.is_active = True
            user.save(update_fields=["status", "is_active"])
            if user.email:
                email_send(
                    "Advertiser account approved",
                    "Your advertiser account has been approved. You can now login and start using your account.",
                    user.email,
                )
        self.message_user(request, f"Approved {advertisers.count()} advertiser account(s).")

    approve_advertisers.short_description = "Approve selected pending advertiser accounts"

    def reject_advertisers(self, request, queryset):
        advertisers = queryset.filter(
            account_type=NormalUser.ACCOUNT_TYPE_ADVERTISER,
            status=NormalUser.STATUS_PENDING,
        )
        for user in advertisers:
            user.status = NormalUser.STATUS_REJECTED
            user.is_active = False
            user.save(update_fields=["status", "is_active"])
            if user.email:
                email_send(
                    "Advertiser account rejected",
                    "Your advertiser account request has been rejected.",
                    user.email,
                )
        self.message_user(request, f"Rejected {advertisers.count()} advertiser account(s).")

    reject_advertisers.short_description = "Reject selected pending advertiser accounts"


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
