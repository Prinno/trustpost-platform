from datetime import timedelta

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import generics, status
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .authentication import create_jwt
from .models import NormalUser, VerificationToken, PhoneOTP, RefreshToken, PendingRegistration, PasswordResetOTP, PasswordResetSession, Post, ModerationAction, UserRestriction
from admin_auth.permissions import IsAdminEnabled, IsSuperAdmin
from admin_auth.models import AdminAccount
from .permissions import IsNormalUser
from .serializers import (
    LoginSerializer,
    NormalUserSerializer,
    NormalUserUpdateSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    PasswordResetOTPVerifySerializer,
    RegisterSerializer,
    RequestEmailVerificationSerializer,
    RequestPhoneOTPSerializer,
    VerifyEmailSerializer,
    VerifyPhoneOTPSerializer,
    PostSerializer,
    UserRestrictionSerializer,
)
from .utils import generate_token, generate_otp, now_utc, email_send


from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.tokens import RefreshToken as SimpleJWTRefreshToken


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
        pending: PendingRegistration = serializer.save()
        # Send verification email with single-use token
        if pending.email:
            verify_url = f"{getattr(settings, 'NORMAL_USER_EMAIL_VERIFY_URL', '/api/auth/verify-email/')}?token={pending.token}"
            email_send("Verify your email", f"Click to verify: {verify_url}", pending.email)
        return Response({
            "detail": "Registration received. Verify your email to activate.",
        }, status=status.HTTP_201_CREATED)




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
            # Prefer username login; keep phone for backward compatibility
            normal_user = NormalUser.objects.filter(username__iexact=identifier).first()
            if not normal_user:
                normal_user = NormalUser.objects.filter(phone=identifier).first()

        if normal_user:
            if not check_password(password, normal_user.password):
                return Response({"detail": "Invalid credentials"}, status=401)

            if not normal_user.is_email_verified:
                return Response({"detail": "Email not verified"}, status=403)

            if not normal_user.is_active:
                return Response({"detail": "Account inactive"}, status=403)

            # Issue app-native JWTs compatible with NormalUserJWTAuthentication
            access = create_jwt({"sub": "normal_user_access", "uid": normal_user.id}, ACCESS_MINUTES)
            refresh_token = create_jwt({"sub": "normal_user_refresh", "uid": normal_user.id}, REFRESH_DAYS * 24 * 60)

            # Persist refresh in DB for server-side validation and revocation
            RefreshToken.objects.create(
                user=normal_user,
                token=refresh_token,
                expires_at=timezone.now() + timedelta(days=REFRESH_DAYS),
            )

            return Response({
                "user_type": "normal",
                "access": access,
                "refresh": refresh_token,
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

        refresh = SimpleJWTRefreshToken.for_user(user)

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

        # Strict flow: pending registration first
        pr = PendingRegistration.objects.filter(token=token).first()
        if pr:
            if not pr.is_valid():
                return Response({"detail": "Invalid or expired token"}, status=400)

            # Re-check uniqueness at verification time
            if NormalUser.objects.filter(username__iexact=pr.username).exists():
                return Response({"detail": "Username already exists"}, status=409)
            if pr.email and NormalUser.objects.filter(email__iexact=pr.email).exists():
                return Response({"detail": "Email already exists"}, status=409)
            if pr.phone and NormalUser.objects.filter(phone=pr.phone).exists():
                return Response({"detail": "Phone already registered"}, status=409)

            user = NormalUser.objects.create(
                username=pr.username,
                email=pr.email,
                phone=pr.phone,
                password=pr.password,
                is_active=True,
                is_email_verified=True,
                is_phone_verified=False,
            )
            pr.used = True
            pr.save(update_fields=["used"])
            pr.delete()

            if user.email:
                email_send("Welcome to TruePost", "Email verified successfully. Please login.", user.email)

            return Response({
                "detail": "Email verified successfully. Please login.",
                "user": NormalUserSerializer(user).data,
            })

        # Legacy flow fallback
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
        email = s.validated_data.get("email")
        user = s.validated_data.get("user")  # may be None

        # Invalidate all previous OTPs for this email (resend logic)
        PasswordResetOTP.objects.filter(email__iexact=email, used=False).update(used=True)

        # If account exists, create and send OTP. Always return generic response.
        if user:
            code = generate_otp()
            PasswordResetOTP.objects.create(
                email=user.email,
                code=code,
                expires_at=now_utc() + timedelta(minutes=getattr(settings, "NORMAL_USER_RESET_OTP_MINUTES", 15)),
            )
            email_send("Your password reset code",
                       f"Use this code to reset your password: {code}\nThis code expires in 15 minutes.",
                       user.email)

        return Response({"detail": "If the email exists, an OTP has been sent."})


class PasswordResetVerifyOTPView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetOTPVerifySerializer

    def post(self, request, *args, **kwargs):
        s = self.get_serializer(data=request.data)
        s.is_valid(raise_exception=True)
        email = s.validated_data.get("email")
        otp = s.validated_data.get("otp")

        # Verify latest active OTP only
        from hmac import compare_digest
        latest = (
            PasswordResetOTP.objects
            .filter(email__iexact=email, used=False, expires_at__gt=timezone.now())
            .order_by("-created_at")
            .first()
        )
        if not latest or not compare_digest(str(latest.code), str(otp)):
            return Response({"detail": "Invalid or expired code"}, status=400)

        # Mark OTP used
        latest.used = True
        latest.save(update_fields=["used"])

        # Create temporary reset session token
        from .utils import generate_token
        token = generate_token()
        session = PasswordResetSession.objects.create(
            email=email,
            token=token,
            expires_at=now_utc() + timedelta(minutes=getattr(settings, "NORMAL_USER_RESET_SESSION_MINUTES", 15)),
        )

        return Response({"detail": "OTP verified. Proceed to reset password.", "reset_token": session.token})


class PasswordResetConfirmView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, *args, **kwargs):
        s = self.get_serializer(data=request.data)
        s.is_valid(raise_exception=True)
        reset_token = s.validated_data.get("reset_token")
        new_password = s.validated_data["new_password"]

        # Require valid reset session token (OTP must already be verified)
        session = PasswordResetSession.objects.filter(token=reset_token).first()
        if not session or not session.is_valid():
            return Response({"detail": "Invalid or expired reset authorization"}, status=400)

        from django.contrib.auth.hashers import make_password
        user = NormalUser.objects.filter(email__iexact=session.email).first()
        if not user:
            return Response({"detail": "Invalid or expired reset authorization"}, status=400)
        user.password = make_password(new_password)
        user.save(update_fields=["password"])

        # Invalidate all OTPs and reset sessions for this email
        PasswordResetOTP.objects.filter(email__iexact=session.email, used=False).update(used=True)
        PasswordResetSession.objects.filter(email__iexact=session.email, used=False).update(used=True)
        session.used = True
        session.save(update_fields=["used"])

        # Notify user
        if user.email:
            email_send(
                "Your password has been changed",
                "If you did not initiate this change, please contact support immediately.",
                user.email,
            )

        return Response({"detail": "Password has been reset. Please login."})


@api_view(["GET"])  # Example protected endpoint
@permission_classes([IsNormalUser])
def me_view(request):
    return Response(NormalUserSerializer(request.user.normal_user).data)


class MeUpdateView(generics.GenericAPIView):
    permission_classes = [IsNormalUser]
    serializer_class = NormalUserUpdateSerializer

    def patch(self, request, *args, **kwargs):
        inst = request.user.normal_user
        s = self.get_serializer(instance=inst, data=request.data, partial=True)
        s.is_valid(raise_exception=True)
        s.save()
        return Response(NormalUserSerializer(inst).data)


class MeAvatarUploadView(generics.GenericAPIView):
    permission_classes = [IsNormalUser]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request, *args, **kwargs):
        user = request.user.normal_user
        avatar = request.FILES.get('avatar')
        if not avatar:
            return Response({'detail': 'No file provided'}, status=400)

        # Save to MEDIA_ROOT/avatars/
        import os
        from django.conf import settings
        from django.core.files.storage import default_storage
        from django.utils.timezone import now

        ext = os.path.splitext(avatar.name)[1].lower() or '.jpg'
        filename = f"avatars/{user.id}_{int(now().timestamp())}{ext}"
        path = default_storage.save(filename, avatar)
        # Build absolute URL
        rel_url = f"{settings.MEDIA_URL}{path}"
        absolute_url = request.build_absolute_uri(rel_url)

        user.avatar_url = absolute_url
        user.save(update_fields=["avatar_url"])
        return Response({"avatar_url": absolute_url})


class MePostListCreateView(generics.ListCreateAPIView):
    permission_classes = [IsNormalUser]
    serializer_class = PostSerializer

    def get_queryset(self):
        return Post.objects.filter(author=self.request.user.normal_user).order_by("-created_at")

    def perform_create(self, serializer):
        serializer.save()


class MeRestrictionsView(generics.ListAPIView):
    permission_classes = [IsNormalUser]
    serializer_class = UserRestrictionSerializer

    def get_queryset(self):
        user = self.request.user.normal_user
        return UserRestriction.objects.filter(user=user)


class MeUploadMediaView(generics.GenericAPIView):
    permission_classes = [IsNormalUser]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request, *args, **kwargs):
        file = request.FILES.get("file")
        if not file:
            return Response({"detail": "No file provided"}, status=400)

        import os
        from django.conf import settings
        from django.core.files.storage import default_storage
        from django.utils.timezone import now

        ext = os.path.splitext(file.name)[1].lower()
        if not ext:
            ext = ".bin"
        filename = f"posts/{request.user.normal_user.id}_{int(now().timestamp())}{ext}"
        path = default_storage.save(filename, file)
        rel_url = f"{settings.MEDIA_URL}{path}"
        absolute_url = request.build_absolute_uri(rel_url)

        media_type = "image"
        if ext in [".mp4", ".mov", ".mkv", ".webm"]:
            media_type = "video"

        return Response({"url": absolute_url, "media_type": media_type})


class AdminPendingPostsListView(generics.ListAPIView):
    permission_classes = [IsAdminEnabled]
    serializer_class = PostSerializer

    def get_queryset(self):
        return Post.objects.filter(status=Post.PENDING).order_by("-created_at")


class AdminApprovePostView(generics.GenericAPIView):
    permission_classes = [IsAdminEnabled]

    def post(self, request, pk, *args, **kwargs):
        # Permission granular check
        acc = getattr(request.user, "admin_account", None)
        if acc and not acc.permissions.get("can_approve", True):
            return Response({"detail": "Not permitted to approve"}, status=403)
        post = get_object_or_404(Post, pk=pk)
        post.status = Post.APPROVED
        post.rejection_reason = None
        post.save(update_fields=["status", "rejection_reason", "updated_at"])
        # Audit log
        actor = request.user
        role = AdminAccount.ROLE_SUPERADMIN if getattr(actor, "is_superuser", False) else AdminAccount.ROLE_ADMIN
        ModerationAction.objects.create(
            post=post,
            actor_username=getattr(actor, "username", str(actor)),
            actor_role=role,
            action=ModerationAction.ACTION_APPROVE,
            reason="",
        )
        return Response(PostSerializer(post).data)


class AdminRejectPostView(generics.GenericAPIView):
    permission_classes = [IsAdminEnabled]

    def post(self, request, pk, *args, **kwargs):
        # Permission granular check
        acc = getattr(request.user, "admin_account", None)
        if acc and not acc.permissions.get("can_reject", True):
            return Response({"detail": "Not permitted to reject"}, status=403)
        post = get_object_or_404(Post, pk=pk)
        reason = (request.data.get("reason") or "").strip()
        if not reason:
            return Response({"detail": "Rejection reason is required"}, status=400)
        post.status = Post.REJECTED
        post.rejection_reason = reason
        post.save(update_fields=["status", "rejection_reason", "updated_at"])

        # Audit log
        actor = request.user
        role = AdminAccount.ROLE_SUPERADMIN if getattr(actor, "is_superuser", False) else AdminAccount.ROLE_ADMIN
        ModerationAction.objects.create(
            post=post,
            actor_username=getattr(actor, "username", str(actor)),
            actor_role=role,
            action=ModerationAction.ACTION_REJECT,
            reason=reason,
        )

        user = post.author
        if user.email:
            try:
                email_send(
                    "Your post was rejected",
                    f"Your post has been rejected by an admin. Reason: {reason}",
                    user.email,
                )
            except Exception:
                pass

        return Response(PostSerializer(post).data)


class AdminIssueWarningView(generics.GenericAPIView):
    permission_classes = [IsAdminEnabled]

    def post(self, request, *args, **kwargs):
        user_id = request.data.get("user_id")
        reason = (request.data.get("reason") or "").strip()
        if not user_id or not reason:
            return Response({"detail": "user_id and reason are required"}, status=400)
        user = get_object_or_404(NormalUser, pk=user_id)
        actor = request.user
        role = AdminAccount.ROLE_SUPERADMIN if getattr(actor, "is_superuser", False) else AdminAccount.ROLE_ADMIN
        ModerationAction.objects.create(
            post=None,
            actor_username=getattr(actor, "username", str(actor)),
            actor_role=role,
            action=ModerationAction.ACTION_WARN,
            reason=reason,
        )
        if user.email:
            try:
                email_send(
                    "Warning issued",
                    f"You have received a warning: {reason}",
                    user.email,
                )
            except Exception:
                pass
        return Response({"detail": "Warning issued"})


class AdminApplyRestrictionView(generics.GenericAPIView):
    permission_classes = [IsAdminEnabled]

    def post(self, request, *args, **kwargs):
        user_id = request.data.get("user_id")
        rtype = request.data.get("type")
        reason = (request.data.get("reason") or "").strip()
        until = request.data.get("until")  # ISO string optional
        if not user_id or not rtype:
            return Response({"detail": "user_id and type are required"}, status=400)
        if rtype not in {UserRestriction.TYPE_POST_SUSPEND, UserRestriction.TYPE_ACCOUNT_SUSPEND}:
            return Response({"detail": "Invalid restriction type"}, status=400)
        user = get_object_or_404(NormalUser, pk=user_id)
        dt_until = None
        if until:
            try:
                from django.utils.dateparse import parse_datetime
                dt_until = parse_datetime(until)
            except Exception:
                return Response({"detail": "Invalid until datetime"}, status=400)
        actor = request.user
        role = AdminAccount.ROLE_SUPERADMIN if getattr(actor, "is_superuser", False) else AdminAccount.ROLE_ADMIN
        UserRestriction.objects.create(
            user=user,
            type=rtype,
            reason=reason,
            until=dt_until,
            created_by=getattr(actor, "username", str(actor)),
        )
        ModerationAction.objects.create(
            post=None,
            actor_username=getattr(actor, "username", str(actor)),
            actor_role=role,
            action=ModerationAction.ACTION_RESTRICT,
            reason=f"{rtype}: {reason}",
        )
        return Response({"detail": "Restriction applied"})


class PublicApprovedPostsView(generics.ListAPIView):
    permission_classes = [AllowAny]
    serializer_class = PostSerializer

    def get_queryset(self):
        return Post.objects.filter(status=Post.APPROVED).order_by("-created_at")
