from datetime import timedelta

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .authentication import create_jwt
from .models import NormalUser, VerificationToken, PhoneOTP, RefreshToken
from .permissions import IsNormalUser
from .serializers import (
    LoginSerializer,
    NormalUserSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    RegisterSerializer,
    RequestEmailVerificationSerializer,
    RequestPhoneOTPSerializer,
    VerifyEmailSerializer,
    VerifyPhoneOTPSerializer,
)
from .utils import generate_token, generate_otp, now_utc, email_send


from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.tokens import RefreshToken


ACCESS_MINUTES = getattr(settings, "NORMAL_USER_JWT_ACCESS_MINUTES", 15)
REFRESH_DAYS = getattr(settings, "NORMAL_USER_JWT_REFRESH_DAYS", 7)
OTP_MINUTES = getattr(settings, "NORMAL_USER_OTP_MINUTES", 10)
VERIFY_TOKEN_HOURS = getattr(settings, "NORMAL_USER_VERIFY_TOKEN_HOURS", 24)


class RegisterView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        if user.email:
            token = generate_token()
            VerificationToken.objects.create(
                user=user,
                token=token,
                type=VerificationToken.EMAIL_VERIFY,
                expires_at=now_utc() + timedelta(hours=VERIFY_TOKEN_HOURS),
            )
            verify_url = f"{getattr(settings, 'NORMAL_USER_EMAIL_VERIFY_URL', '/api/auth/verify-email/')}?token={token}"
            email_send("Verify your email", f"Click to verify: {verify_url}", user.email)
        if user.phone:
            code = generate_otp()
            PhoneOTP.objects.create(
                user=user,
                code=code,
                expires_at=now_utc() + timedelta(minutes=OTP_MINUTES),
            )
            # In production, integrate an SMS provider here.
            # For now, we log to console via email backend or server logs.
            print(f"OTP for {user.phone}: {code}")
        return Response({"message": "Registered. Complete verification.", "user": NormalUserSerializer(user).data}, status=status.HTTP_201_CREATED)




class LoginView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        identifier = serializer.validated_data["identifier"].strip()
        password = serializer.validated_data["password"]

        # ==================================================
        # 1️⃣ NORMAL USER AUTH
        # ==================================================
        if "@" in identifier:
            normal_user = NormalUser.objects.filter(email__iexact=identifier).first()
        else:
            normal_user = NormalUser.objects.filter(phone=identifier).first()

        if normal_user:
            if not check_password(password, normal_user.password):
                return Response({"detail": "Invalid credentials"}, status=401)

            if not normal_user.is_email_verified:
                return Response({"detail": "Email not verified"}, status=403)

            if not normal_user.is_active:
                return Response({"detail": "Account inactive"}, status=403)

            refresh = RefreshToken()
            refresh["uid"] = normal_user.id
            refresh["user_type"] = "normal"

            return Response({
                "user_type": "normal",
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "user": NormalUserSerializer(normal_user).data,
            }, status=200)

        # ==================================================
        # 2️⃣ ADMIN / SUPERADMIN AUTH
        # ==================================================
        User = get_user_model()
        username = identifier

        if "@" in identifier:
            user_obj = User.objects.filter(email__iexact=identifier).first()
            if not user_obj:
                return Response({"detail": "Invalid credentials"}, status=401)
            username = user_obj.get_username()

        user = authenticate(username=username, password=password)

        if not user or not (user.is_staff or user.is_superuser):
            return Response({"detail": "Invalid credentials"}, status=401)

        refresh = RefreshToken.for_user(user)

        return Response({
            "user_type": "superadmin" if user.is_superuser else "admin",
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": {
                "id": user.id,
                "username": user.get_username(),
                "email": user.email,
            },
        }, status=200)

# class LoginView(generics.GenericAPIView):
#     permission_classes = [AllowAny]
#     serializer_class = LoginSerializer

#     def post(self, request, *args, **kwargs):
#         s = self.get_serializer(data=request.data)
#         s.is_valid(raise_exception=True)
#         identifier = s.validated_data["identifier"].strip()
#         password = s.validated_data["password"]

#         # 1) Try NormalUser first
#         nu = None
#         if "@" in identifier:
#             nu = NormalUser.objects.filter(email=identifier).first()
#         else:
#             nu = NormalUser.objects.filter(phone=identifier).first()

#         from django.contrib.auth.hashers import check_password

#         if nu and check_password(password, nu.password):
#             # Ensure verification/inactive checks
#             if not nu.is_email_verified:
#                 return Response({"detail": "Email not verified"}, status=403)
#             if not nu.is_active:
#                 return Response({"detail": "Account inactive"}, status=403)
#             access = create_jwt({"sub": "normal_user_access", "uid": nu.id}, ACCESS_MINUTES)
#             refresh = create_jwt({"sub": "normal_user_refresh", "uid": nu.id}, REFRESH_DAYS * 24 * 60)
#             RefreshToken.objects.create(
#                 user=nu,
#                 token=refresh,
#                 expires_at=timezone.now() + timedelta(days=REFRESH_DAYS),
#             )
#             return Response({
#                 "user_type": "normal",
#                 "token": access,
#                 "refresh": refresh,
#                 "user": NormalUserSerializer(nu).data,
#             })

#         # 2) Fallback to Django User (admin/superadmin)
#         User = get_user_model()
#         username = identifier
#         if "@" in identifier:
#             user_obj = User.objects.filter(email=identifier).first()
#             if not user_obj:
#                 return Response({"detail": "Invalid credentials"}, status=401)
#             username = user_obj.get_username()
#         user = authenticate(username=username, password=password)
#         if not user:
#             return Response({"detail": "Invalid credentials"}, status=401)
#         if not (user.is_staff or user.is_superuser):
#             # Not allowed to login via app if not admin or superadmin
#             return Response({"detail": "Invalid credentials"}, status=401)

#         from rest_framework_simplejwt.tokens import RefreshToken

#         refresh = RefreshToken.for_user(user)

#         return Response({
#             "user_type": "superadmin" if user.is_superuser else "admin",
#             "access": str(refresh.access_token),
#             "refresh": str(refresh),
#             "user": {
#                 "id": user.id,
#                 "username": user.get_username(),
#                 "email": user.email,
#             }
#         })



@api_view(["POST"])
@permission_classes([AllowAny])
def refresh_view(request):
    token = request.data.get("refresh")
    if not token:
        return Response({"detail": "Missing refresh token"}, status=400)
    rt = RefreshToken.objects.filter(token=token, revoked=False, expires_at__gt=timezone.now()).first()
    if not rt:
        return Response({"detail": "Invalid refresh token"}, status=401)
    user = rt.user
    access = create_jwt({"sub": "normal_user_access", "uid": user.id}, ACCESS_MINUTES)
    return Response({"access": access})


@api_view(["POST"])
@permission_classes([AllowAny])
def logout_view(request):
    token = request.data.get("refresh")
    if not token:
        return Response({"detail": "Missing refresh token"}, status=400)
    updated = RefreshToken.objects.filter(token=token, revoked=False).update(revoked=True)
    if not updated:
        return Response({"detail": "Already logged out or invalid"}, status=200)
    return Response({"detail": "Logged out"})


class RequestEmailVerificationView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = RequestEmailVerificationSerializer

    def post(self, request, *args, **kwargs):
        s = self.get_serializer(data=request.data)
        s.is_valid(raise_exception=True)
        user = s.validated_data["user"]
          # 🔹 invalidate old tokens (SAFE)
        VerificationToken.objects.filter(
            user=user,
            type=VerificationToken.EMAIL_VERIFY,
            used=False
        ).update(used=True)

        token = generate_token()
        VerificationToken.objects.create(
            user=user,
            token=token,
            type=VerificationToken.EMAIL_VERIFY,
            expires_at=now_utc() + timedelta(hours=VERIFY_TOKEN_HOURS),
        )
        verify_url = f"{getattr(settings, 'NORMAL_USER_EMAIL_VERIFY_URL', '/api/auth/verify-email/')}?token={token}"
        email_send("Verify your email", f"Click to verify: {verify_url}", user.email)
        return Response({"detail": "Verification email sent"})


class VerifyEmailView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = VerifyEmailSerializer

    def get(self, request, *args, **kwargs):
        token = request.query_params.get("token")
        if not token:
            return Response({"detail": "Missing token"}, status=400)
        vt = VerificationToken.objects.filter(token=token, type=VerificationToken.EMAIL_VERIFY).first()
        if not vt or not vt.is_valid():
            return Response({"detail": "Invalid or expired token"}, status=400)
        vt.used = True
        vt.save(update_fields=["used"])
        user = vt.user
        user.is_email_verified = True
        if user.is_phone_verified:
            user.is_active = True
        user.save(update_fields=["is_email_verified", "is_active"])
        return Response({"detail": "Email verified", "user": NormalUserSerializer(user).data})


class RequestPhoneOTPView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = RequestPhoneOTPSerializer

    def post(self, request, *args, **kwargs):
        s = self.get_serializer(data=request.data)
        s.is_valid(raise_exception=True)
        user = s.validated_data["user"]
        code = generate_otp()
        PhoneOTP.objects.create(
            user=user,
            code=code,
            expires_at=now_utc() + timedelta(minutes=OTP_MINUTES),
        )
        print(f"OTP for {user.phone}: {code}")
        return Response({"detail": "OTP sent"})


class VerifyPhoneOTPView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = VerifyPhoneOTPSerializer

    def post(self, request, *args, **kwargs):
        s = self.get_serializer(data=request.data)
        s.is_valid(raise_exception=True)
        phone = s.validated_data["phone"]
        code = s.validated_data["code"]
        user = get_object_or_404(NormalUser, phone=phone)
        otp = (
            PhoneOTP.objects.filter(user=user, used=False, expires_at__gt=timezone.now())
            .order_by("-created_at")
            .first()
        )
        if not otp or otp.code != code:
            if otp:
                otp.attempt_count += 1
                otp.save(update_fields=["attempt_count"])
            return Response({"detail": "Invalid or expired code"}, status=400)
        otp.used = True
        otp.save(update_fields=["used"])
        user.is_phone_verified = True
        if user.is_email_verified:
            user.is_active = True
        user.save(update_fields=["is_phone_verified", "is_active"])
        return Response({"detail": "Phone verified", "user": NormalUserSerializer(user).data})


class PasswordResetRequestView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetRequestSerializer

    def post(self, request, *args, **kwargs):
        s = self.get_serializer(data=request.data)
        s.is_valid(raise_exception=True)
        user = s.validated_data["user"]
        if user.email and request.data.get("email"):
            token = generate_token()
            VerificationToken.objects.create(
                user=user,
                token=token,
                type=VerificationToken.PASSWORD_RESET,
                expires_at=now_utc() + timedelta(hours=VERIFY_TOKEN_HOURS),
            )
            reset_url = f"{getattr(settings, 'NORMAL_USER_PASSWORD_RESET_URL', '/api/auth/password-reset/confirm/')}?token={token}"
            email_send("Reset your password", f"Open to reset: {reset_url}", user.email)
            return Response({"detail": "Password reset email sent"})
        if user.phone and request.data.get("phone"):
            code = generate_otp()
            PhoneOTP.objects.create(
                user=user,
                code=code,
                expires_at=now_utc() + timedelta(minutes=OTP_MINUTES),
            )
            print(f"Password reset OTP for {user.phone}: {code}")
            return Response({"detail": "Password reset OTP sent"})
        return Response({"detail": "No valid channel for reset"}, status=400)


class PasswordResetConfirmView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, *args, **kwargs):
        s = self.get_serializer(data=request.data)
        s.is_valid(raise_exception=True)
        token = s.validated_data.get("token")
        phone = s.validated_data.get("phone")
        code = s.validated_data.get("code")
        new_password = s.validated_data["new_password"]

        user = None
        if token:
            vt = VerificationToken.objects.filter(token=token, type=VerificationToken.PASSWORD_RESET).first()
            if not vt or not vt.is_valid():
                return Response({"detail": "Invalid or expired token"}, status=400)
            vt.used = True
            vt.save(update_fields=["used"])
            user = vt.user
        elif phone and code:
            try:
                user = NormalUser.objects.get(phone=phone)
            except NormalUser.DoesNotExist:
                return Response({"detail": "Account not found"}, status=404)
            otp = (
                PhoneOTP.objects.filter(user=user, used=False, expires_at__gt=timezone.now())
                .order_by("-created_at")
                .first()
            )
            if not otp or otp.code != code:
                if otp:
                    otp.attempt_count += 1
                    otp.save(update_fields=["attempt_count"])
                return Response({"detail": "Invalid or expired code"}, status=400)
            otp.used = True
            otp.save(update_fields=["used"])
        else:
            return Response({"detail": "Provide token or phone+code"}, status=400)

        from django.contrib.auth.hashers import make_password

        user.password = make_password(new_password)
        user.save(update_fields=["password"])
        return Response({"detail": "Password has been reset"})


@api_view(["GET"])  # Example protected endpoint
@permission_classes([IsNormalUser])
def me_view(request):
    return Response(NormalUserSerializer(request.user.normal_user).data)
