from django.urls import path
from .views import (
    RegisterView,
    LoginView,
    RequestEmailVerificationView,
    VerifyEmailView,
    RequestPhoneOTPView,
    VerifyPhoneOTPView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
    refresh_view,
    logout_view,
    me_view,
)

urlpatterns = [
    path("register/", RegisterView.as_view(), name="nu-register"),
    path("login/", LoginView.as_view(), name="nu-login"),
    path("refresh/", refresh_view, name="nu-refresh"),
    path("logout/", logout_view, name="nu-logout"),

    path("request-email-verification/", RequestEmailVerificationView.as_view(), name="nu-request-email-verification"),
    path("verify-email/", VerifyEmailView.as_view(), name="nu-verify-email"),

    path("request-phone-otp/", RequestPhoneOTPView.as_view(), name="nu-request-phone-otp"),
    path("verify-phone-otp/", VerifyPhoneOTPView.as_view(), name="nu-verify-phone-otp"),

    path("password-reset/request/", PasswordResetRequestView.as_view(), name="nu-password-reset-request"),
    path("password-reset/confirm/", PasswordResetConfirmView.as_view(), name="nu-password-reset-confirm"),

    path("me/", me_view, name="nu-me"),
]
