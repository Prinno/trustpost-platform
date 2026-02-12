from datetime import timedelta

from django.conf import settings
from django.db import models
from django.contrib.auth import authenticate, get_user_model
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import generics, status
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .authentication import create_jwt
from .models import NormalUser, VerificationToken, PhoneOTP, RefreshToken, PendingRegistration, PasswordResetOTP, PasswordResetSession, Post, PostItem, ModerationAction, UserRestriction, PostVersion, Feedback, PostView, Comment, PostReaction, RewardTransaction, UserTokenBalance, UserFollow, UserBlock
from admin_auth.permissions import IsAdminEnabled, IsSuperAdmin
from admin_auth.models import AdminAccount
from admin_auth.permissions import IsSuperAdmin
from .permissions import IsNormalUser
from .serializers import (
    LoginSerializer,
    NormalUserSerializer,
    PublicUserSerializer,
    UserSearchResultSerializer,
    UserProfileSerializer,
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
    FeedbackSerializer,
    RewardTransactionSerializer,
    CommentSerializer,
    CommentCreateSerializer,
)
from .services.comment_service import (
    create_comment,
    edit_comment,
    soft_delete_comment,
    get_top_level_comments_queryset,
    get_replies_queryset,
)
from .utils import generate_token, generate_otp, now_utc, email_send


from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.tokens import RefreshToken as SimpleJWTRefreshToken
from django.db.models import Count, Exists, OuterRef, Case, When, Value, IntegerField


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


class NormalUserListView(generics.ListAPIView):
    """List active, verified normal users (excluding current user), with optional search.

    Query params:
      - q: search term matching username or public_username (case-insensitive)
      - limit: optional max results (default 100)
    """
    permission_classes = [IsNormalUser]
    serializer_class = PublicUserSerializer

    def get_queryset(self):
        q = self.request.query_params.get("q", "").strip()
        try:
            limit = int(self.request.query_params.get("limit", 100))
        except Exception:
            limit = 100
        qs = NormalUser.objects.filter(is_active=True, is_email_verified=True)
        me = getattr(self.request.user, "normal_user", None)
        if me:
            qs = qs.exclude(pk=me.id)
        if q:
            qs = qs.filter(
                models.Q(username__icontains=q) | models.Q(public_username__icontains=q)
            )
        return qs.order_by("username", "id")[: max(1, min(500, limit))]


class _PublicUserQueryMixin:
    """Shared helpers for public user discovery/search/profile.

    Ensures we always filter by active, verified, non-private, discoverable
    users and apply mutual block rules.
    """

    def _base_public_qs(self, request):
        me = getattr(getattr(request, "user", None), "normal_user", None)
        qs = NormalUser.objects.filter(
            is_active=True,
            is_email_verified=True,
            is_private=False,
            allow_discovery=True,
        )
        if me:
            qs = qs.exclude(pk=me.id)
            # Exclude users where there is any block relation in either
            # direction between the current user and the candidate.
            outgoing = UserBlock.objects.filter(
                blocker=me,
                blocked=OuterRef("pk"),
            )
            incoming = UserBlock.objects.filter(
                blocker=OuterRef("pk"),
                blocked=me,
            )
            qs = qs.annotate(
                _blocked_by_me=Exists(outgoing),
                _blocked_me=Exists(incoming),
            ).filter(_blocked_by_me=False, _blocked_me=False)
        return qs


class UserDiscoverView(_PublicUserQueryMixin, generics.GenericAPIView):
    """Cursor-based random user discovery for the search tab.

    - Excludes current user, private accounts, and blocked users.
    - Uses an indexed approach instead of ORDER BY RANDOM() by choosing
      a random starting id and walking forward, then wrapping around.
    """

    permission_classes = [IsNormalUser]
    serializer_class = UserSearchResultSerializer
    PAGE_SIZE_DEFAULT = 20
    PAGE_SIZE_MAX = 50

    def _encode_cursor(self, last_id: int) -> str:
        import base64, json

        payload = json.dumps({"last_id": last_id}).encode("utf-8")
        return base64.urlsafe_b64encode(payload).decode("ascii")

    def _decode_cursor(self, cursor: str):
        import base64, json

        try:
            data = base64.urlsafe_b64decode(cursor.encode("ascii"))
            obj = json.loads(data.decode("utf-8"))
            return int(obj.get("last_id"))
        except Exception:
            return None

    def get(self, request, *args, **kwargs):
        try:
            page_size = int(request.query_params.get("page_size", self.PAGE_SIZE_DEFAULT))
        except Exception:
            page_size = self.PAGE_SIZE_DEFAULT
        page_size = max(1, min(self.PAGE_SIZE_MAX, page_size))

        cursor = request.query_params.get("cursor")
        base_qs = self._base_public_qs(request).annotate(
            followers_count=Count("follower_relations", distinct=True),
        )

        if not base_qs.exists():
            return Response({"results": [], "next_cursor": None})

        if cursor:
            last_id = self._decode_cursor(cursor)
            if last_id is None:
                return Response({"detail": "Invalid cursor"}, status=400)
            qs = base_qs.filter(id__gt=last_id).order_by("id")
            users = list(qs[:page_size])
        else:
            # Choose a random starting id in the id range to avoid full table
            # scans/sorts. This leverages the primary key index and is
            # scalable to large user counts.
            import random

            max_id = base_qs.order_by("-id").values_list("id", flat=True).first()
            if not max_id:
                return Response({"results": [], "next_cursor": None})
            start_id = random.randint(1, max_id)
            primary = list(base_qs.filter(id__gte=start_id).order_by("id")[:page_size])
            if len(primary) >= page_size:
                users = primary
            else:
                remaining = page_size - len(primary)
                wrap = list(base_qs.filter(id__lt=start_id).order_by("id")[:remaining])
                users = primary + wrap

        if not users:
            return Response({"results": [], "next_cursor": None})

        data = self.get_serializer(users, many=True).data
        next_cursor = self._encode_cursor(users[-1].id) if len(users) == page_size else None
        return Response({"results": data, "next_cursor": next_cursor})


class UserSearchView(_PublicUserQueryMixin, generics.GenericAPIView):
    """Username/full-name search with ranking and cursor pagination."""

    permission_classes = [IsNormalUser]
    serializer_class = UserSearchResultSerializer
    PAGE_SIZE_DEFAULT = 20
    PAGE_SIZE_MAX = 50

    def _encode_cursor(self, last_id: int) -> str:
        import base64, json

        payload = json.dumps({"last_id": last_id}).encode("utf-8")
        return base64.urlsafe_b64encode(payload).decode("ascii")

    def _decode_cursor(self, cursor: str):
        import base64, json

        try:
            data = base64.urlsafe_b64decode(cursor.encode("ascii"))
            obj = json.loads(data.decode("utf-8"))
            return int(obj.get("last_id"))
        except Exception:
            return None

    def get(self, request, *args, **kwargs):
        q = (request.query_params.get("q", "") or "").strip()
        # Basic abuse prevention: require minimal length.
        if len(q) < 2:
            return Response({"results": [], "next_cursor": None})

        try:
            page_size = int(request.query_params.get("page_size", self.PAGE_SIZE_DEFAULT))
        except Exception:
            page_size = self.PAGE_SIZE_DEFAULT
        page_size = max(1, min(self.PAGE_SIZE_MAX, page_size))

        cursor = request.query_params.get("cursor")
        base_qs = self._base_public_qs(request)

        qs = base_qs.filter(
            models.Q(username__icontains=q)
            | models.Q(public_username__icontains=q)
            | models.Q(full_name__icontains=q)
        ).annotate(
            followers_count=Count("follower_relations", distinct=True),
            exact_username=Case(
                When(username__iexact=q, then=Value(1)),
                default=Value(0),
                output_field=IntegerField(),
            ),
            exact_public_username=Case(
                When(public_username__iexact=q, then=Value(1)),
                default=Value(0),
                output_field=IntegerField(),
            ),
            exact_full_name=Case(
                When(full_name__iexact=q, then=Value(1)),
                default=Value(0),
                output_field=IntegerField(),
            ),
        ).order_by(
            "-exact_username",
            "-exact_public_username",
            "-exact_full_name",
            "id",
        )

        if cursor:
            last_id = self._decode_cursor(cursor)
            if last_id is None:
                return Response({"detail": "Invalid cursor"}, status=400)
            qs = qs.filter(id__gt=last_id)

        users = list(qs[:page_size])
        if not users:
            return Response({"results": [], "next_cursor": None})

        data = self.get_serializer(users, many=True).data
        next_cursor = self._encode_cursor(users[-1].id) if len(users) == page_size else None
        return Response({"results": data, "next_cursor": next_cursor})

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
        # Store and return RELATIVE media path to remain IP-agnostic
        user.avatar_url = rel_url
        user.save(update_fields=["avatar_url"])
        return Response({"avatar_url": rel_url})


class MePostListCreateView(generics.ListCreateAPIView):
    permission_classes = [IsNormalUser]
    serializer_class = PostSerializer

    def get_queryset(self):
        return Post.objects.filter(author=self.request.user.normal_user).order_by("-created_at")

    def perform_create(self, serializer):
        serializer.save()


class MePostEditView(generics.GenericAPIView):
    """Allow a normal user to edit own post content.
    - If post is APPROVED, create a pending version and mark post as PENDING_REAPPROVAL.
    - Keep last approved version for public display.
    - Users cannot edit system metadata (author, moderation fields, status).
    """
    permission_classes = [IsNormalUser]
    serializer_class = PostSerializer

    def patch(self, request, pk, *args, **kwargs):
        post = get_object_or_404(Post, pk=pk, author=request.user.normal_user)

        # Only allow content fields
        mode = request.data.get("mode", post.mode)
        main_text = (request.data.get("main_text") or post.main_text or "").strip()
        items = request.data.get("items")

        # Update content snapshot to post records
        post.mode = mode
        post.main_text = main_text

        # Replace items if provided
        if isinstance(items, list):
            PostItem.objects.filter(post=post).delete()
            for order, it in enumerate(items):
                PostItem.objects.create(
                    post=post,
                    media_type=it.get("media_type") or PostItem.IMAGE,
                    file_url=it.get("file_url"),
                    caption_text=(it.get("caption_text") or ""),
                    order=it.get("order", order),
                )

        # Versioning: create pending version
        next_ver = (post.versions.aggregate(models.Max("version")).get("version__max") or 0) + 1
        from django.core.serializers.json import DjangoJSONEncoder
        import json
        snap_items = []
        for it in PostItem.objects.filter(post=post).order_by("order", "id"):
            snap_items.append({
                "media_type": it.media_type,
                "file_url": it.file_url,
                "caption_text": it.caption_text,
                "order": it.order,
            })
        PostVersion.objects.create(
            post=post,
            version=next_ver,
            editor_user=request.user.normal_user,
            status=PostVersion.STATUS_PENDING,
            mode=post.mode,
            main_text=post.main_text,
            items_json=json.dumps(snap_items, cls=DjangoJSONEncoder),
        )

        # Transition status based on previous state
        # - If previously approved: require re-approval but keep last approved snapshot public
        # - If previously rejected: move back to pending and clear rejection reason
        if post.status == Post.APPROVED:
            post.status = Post.PENDING_REAPPROVAL
            post.save(update_fields=["mode", "main_text", "status", "updated_at"])
        elif post.status == Post.REJECTED:
            post.status = Post.PENDING
            post.rejection_reason = None
            post.save(update_fields=["mode", "main_text", "status", "rejection_reason", "updated_at"])
        else:
            # Pending or other: remain pending-like
            post.status = Post.PENDING if post.status != Post.PENDING_REAPPROVAL else post.status
            post.save(update_fields=["mode", "main_text", "status", "updated_at"])
        return Response(PostSerializer(post).data)


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

        media_type = "image"
        if ext in [".mp4", ".mov", ".mkv", ".webm"]:
            media_type = "video"

        # Return relative path; Flutter client will prepend BASE_URL
        return Response({"url": rel_url, "media_type": media_type})


class AdminUploadMediaView(generics.GenericAPIView):
    permission_classes = [IsAdminEnabled]
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
        # Use 'posts/' path similarly; admin author id not tied to NormalUser
        filename = f"posts/admin_{getattr(request.user, 'id', 'x')}_{int(now().timestamp())}{ext}"
        path = default_storage.save(filename, file)
        rel_url = f"{settings.MEDIA_URL}{path}"

        media_type = "image"
        if ext in [".mp4", ".mov", ".mkv", ".webm"]:
            media_type = "video"

        # Return relative path; Flutter client will prepend BASE_URL
        return Response({"url": rel_url, "media_type": media_type})


class AdminPendingPostsListView(generics.ListAPIView):
    permission_classes = [IsAdminEnabled]
    serializer_class = PostSerializer

    def get_queryset(self):
        # Include both fresh pending and pending re-approval edits
        return Post.objects.filter(
            models.Q(status=Post.PENDING) | models.Q(status=getattr(Post, 'PENDING_REAPPROVAL', Post.PENDING))
        ).order_by("-created_at")
        
class AdminPostCreateView(generics.CreateAPIView):
    """Admin/SuperAdmin create posts using same serializer/validation.
    Content is created as PENDING by default; use publish API to approve.
    """
    permission_classes = [IsAdminEnabled]
    serializer_class = PostSerializer

    def perform_create(self, serializer):
        serializer.save()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            # Log serializer errors for easier debugging
            try:
                print("AdminPostCreateView validation errors:", serializer.errors)
            except Exception:
                pass
            return Response(serializer.errors, status=400)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=201, headers=headers)


class AdminPublishPostView(generics.GenericAPIView):
    permission_classes = [IsAdminEnabled]

    def post(self, request, pk, *args, **kwargs):
        post = get_object_or_404(Post, pk=pk)
        # Only admin-authored or normal-authored posts can be published; rules equal for roles
        # Approve and snapshot
        post.status = Post.APPROVED
        post.rejection_reason = None
        post.save(update_fields=["status", "rejection_reason", "updated_at"])

        actor = request.user
        role = AdminAccount.ROLE_SUPERADMIN if getattr(actor, "is_superuser", False) else AdminAccount.ROLE_ADMIN
        ModerationAction.objects.create(
            post=post,
            actor_username=getattr(actor, "username", str(actor)),
            actor_role=role,
            action=ModerationAction.ACTION_APPROVE,
            reason="Admin publish",
        )

        next_ver = (post.versions.aggregate(models.Max("version")).get("version__max") or 0) + 1
        import json
        from django.core.serializers.json import DjangoJSONEncoder
        snap_items = []
        for it in PostItem.objects.filter(post=post).order_by("order", "id"):
            snap_items.append({
                "media_type": it.media_type,
                "file_url": it.file_url,
                "caption_text": it.caption_text,
                "order": it.order,
            })
        PostVersion.objects.create(
            post=post,
            version=next_ver,
            editor_admin_username=getattr(actor, "username", str(actor)),
            editor_role=role,
            status=PostVersion.STATUS_APPROVED,
            mode=post.mode,
            main_text=post.main_text,
            items_json=json.dumps(snap_items, cls=DjangoJSONEncoder),
        )
        post.last_approved_version = next_ver
        post.save(update_fields=["last_approved_version", "updated_at"])
        return Response(PostSerializer(post).data)


# SuperAdmin immediate publish endpoint removed per request; use Admin create + moderation flow.


class AdminRejectedPostsListView(generics.ListAPIView):
    permission_classes = [IsAdminEnabled]
    serializer_class = PostSerializer

    def get_queryset(self):
        return Post.objects.filter(status=Post.REJECTED).order_by("-created_at")


class AdminApprovePostView(generics.GenericAPIView):
    permission_classes = [IsAdminEnabled]

    def post(self, request, pk, *args, **kwargs):
        # Permission granular check
        acc = getattr(request.user, "admin_account", None)
        if acc and not acc.permissions.get("can_approve", True):
            return Response({"detail": "Not permitted to approve"}, status=403)
        post = get_object_or_404(Post, pk=pk)
        # Safety: only allow approve for pending states
        if post.status not in {Post.PENDING, getattr(Post, 'PENDING_REAPPROVAL', Post.PENDING)}:
            return Response({"detail": "Cannot approve in current status"}, status=400)
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
        # Snapshot approved version
        next_ver = (post.versions.aggregate(models.Max("version")).get("version__max") or 0) + 1
        import json
        from django.core.serializers.json import DjangoJSONEncoder
        snap_items = []
        for it in PostItem.objects.filter(post=post).order_by("order", "id"):
            snap_items.append({
                "media_type": it.media_type,
                "file_url": it.file_url,
                "caption_text": it.caption_text,
                "order": it.order,
            })
        PostVersion.objects.create(
            post=post,
            version=next_ver,
            editor_admin_username=getattr(actor, "username", str(actor)),
            editor_role=role,
            status=PostVersion.STATUS_APPROVED,
            mode=post.mode,
            main_text=post.main_text,
            items_json=json.dumps(snap_items, cls=DjangoJSONEncoder),
        )
        post.last_approved_version = next_ver
        post.save(update_fields=["last_approved_version", "updated_at"])
        return Response(PostSerializer(post).data)


class AdminUpdateRejectionReasonView(generics.GenericAPIView):
    permission_classes = [IsAdminEnabled]

    def patch(self, request, pk, *args, **kwargs):
        post = get_object_or_404(Post, pk=pk)
        if post.status != Post.REJECTED:
            return Response({"detail": "Post is not rejected"}, status=400)
        reason = (request.data.get("reason") or "").strip()
        post.rejection_reason = reason
        post.save(update_fields=["rejection_reason", "updated_at"])
        # Audit log
        actor = request.user
        role = AdminAccount.ROLE_SUPERADMIN if getattr(actor, "is_superuser", False) else AdminAccount.ROLE_ADMIN
        ModerationAction.objects.create(
            post=post,
            actor_username=getattr(actor, "username", str(actor)),
            actor_role=role,
            action=ModerationAction.ACTION_EDIT,
            reason=f"Update rejection reason: {reason}",
        )
        return Response(PostSerializer(post).data)


class AdminDeletePostView(generics.DestroyAPIView):
    permission_classes = [IsAdminEnabled]

    def delete(self, request, pk, *args, **kwargs):
        post = get_object_or_404(Post, pk=pk)
        post.delete()
        return Response(status=204)


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


class AdminEditPostView(generics.GenericAPIView):
    """Admin/SuperAdmin can edit any post and set status.
    If set to APPROVED, snapshot as approved version and update last_approved_version.
    """
    permission_classes = [IsAdminEnabled]
    serializer_class = PostSerializer

    def patch(self, request, pk, *args, **kwargs):
        post = get_object_or_404(Post, pk=pk)
        mode = request.data.get("mode", post.mode)
        main_text = (request.data.get("main_text") or post.main_text or "").strip()
        items = request.data.get("items")
        new_status = (request.data.get("status") or post.status)

        post.mode = mode
        post.main_text = main_text
        if isinstance(items, list):
            PostItem.objects.filter(post=post).delete()
            for order, it in enumerate(items):
                PostItem.objects.create(
                    post=post,
                    media_type=it.get("media_type") or PostItem.IMAGE,
                    file_url=it.get("file_url"),
                    caption_text=(it.get("caption_text") or ""),
                    order=it.get("order", order),
                )

        actor = request.user
        role = AdminAccount.ROLE_SUPERADMIN if getattr(actor, "is_superuser", False) else AdminAccount.ROLE_ADMIN

        import json
        from django.core.serializers.json import DjangoJSONEncoder
        snap_items = []
        for it in PostItem.objects.filter(post=post).order_by("order", "id"):
            snap_items.append({
                "media_type": it.media_type,
                "file_url": it.file_url,
                "caption_text": it.caption_text,
                "order": it.order,
            })

        # If explicitly approving
        if new_status == Post.APPROVED:
            post.status = Post.APPROVED
            post.rejection_reason = None
            post.save(update_fields=["status", "rejection_reason", "mode", "main_text", "updated_at"])

            next_ver = (post.versions.aggregate(models.Max("version")).get("version__max") or 0) + 1
            PostVersion.objects.create(
                post=post,
                version=next_ver,
                editor_admin_username=getattr(actor, "username", str(actor)),
                editor_role=role,
                status=PostVersion.STATUS_APPROVED,
                mode=post.mode,
                main_text=post.main_text,
                items_json=json.dumps(snap_items, cls=DjangoJSONEncoder),
            )
            post.last_approved_version = next_ver
            post.save(update_fields=["last_approved_version", "updated_at"])
            ModerationAction.objects.create(
                post=post,
                actor_username=getattr(actor, "username", str(actor)),
                actor_role=role,
                action=ModerationAction.ACTION_EDIT,
                reason="Approved edit",
            )
        elif new_status == Post.REJECTED:
            post.status = Post.REJECTED
            post.save(update_fields=["status", "mode", "main_text", "updated_at"])
            ModerationAction.objects.create(
                post=post,
                actor_username=getattr(actor, "username", str(actor)),
                actor_role=role,
                action=ModerationAction.ACTION_EDIT,
                reason="Rejected edit",
            )
        else:
            # Pending edit: if previously approved, mark pending re-approval
            post.status = Post.PENDING_REAPPROVAL if post.last_approved_version else Post.PENDING
            post.save(update_fields=["status", "mode", "main_text", "updated_at"])
            next_ver = (post.versions.aggregate(models.Max("version")).get("version__max") or 0) + 1
            PostVersion.objects.create(
                post=post,
                version=next_ver,
                editor_admin_username=getattr(actor, "username", str(actor)),
                editor_role=role,
                status=PostVersion.STATUS_PENDING,
                mode=post.mode,
                main_text=post.main_text,
                items_json=json.dumps(snap_items, cls=DjangoJSONEncoder),
            )
        return Response(PostSerializer(post).data)


class AdminRollbackPostView(generics.GenericAPIView):
    permission_classes = [IsAdminEnabled]

    def post(self, request, pk, version, *args, **kwargs):
        post = get_object_or_404(Post, pk=pk)
        pv = get_object_or_404(PostVersion, post=post, version=version, status=PostVersion.STATUS_APPROVED)
        # Apply snapshot
        post.mode = pv.mode
        post.main_text = pv.main_text
        PostItem.objects.filter(post=post).delete()
        import json
        items = []
        try:
            items = json.loads(pv.items_json or "[]")
        except Exception:
            items = []
        for order, it in enumerate(items):
            PostItem.objects.create(
                post=post,
                media_type=it.get("media_type") or PostItem.IMAGE,
                file_url=it.get("file_url"),
                caption_text=(it.get("caption_text") or ""),
                order=it.get("order", order),
            )
        post.status = Post.APPROVED
        post.last_approved_version = pv.version
        post.save(update_fields=["mode", "main_text", "status", "last_approved_version", "updated_at"])
        actor = request.user
        role = AdminAccount.ROLE_SUPERADMIN if getattr(actor, "is_superuser", False) else AdminAccount.ROLE_ADMIN
        ModerationAction.objects.create(
            post=post,
            actor_username=getattr(actor, "username", str(actor)),
            actor_role=role,
            action=ModerationAction.ACTION_EDIT,
            reason=f"Rollback to version {pv.version}",
        )
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
        # Include posts in pending re-approval but still show their last approved snapshot
        # Annotate each post with total likes to avoid N+1 queries.
        return (
            Post.objects
            .filter(models.Q(status=Post.APPROVED) | models.Q(status=Post.PENDING_REAPPROVAL))
            .annotate(
                like_count=Count(
                    "reactions",
                    filter=models.Q(reactions__reaction_type=PostReaction.REACT_LIKE),
                ),
            )
            .order_by("-created_at")
        )

    def get_serializer_context(self):
        ctx = super().get_serializer_context()
        ctx["is_public"] = True
        return ctx


class UserPublicProfileView(_PublicUserQueryMixin, generics.GenericAPIView):
    """Read-only public profile for another normal user.

    Applies privacy, discovery, and block rules, and returns aggregated
    follower/following/post counts.
    """

    permission_classes = [IsNormalUser]
    serializer_class = UserProfileSerializer

    def get(self, request, pk, *args, **kwargs):
        base_qs = self._base_public_qs(request)
        qs = base_qs.filter(pk=pk).annotate(
            followers_count=Count("follower_relations", distinct=True),
            following_count=Count("following_relations", distinct=True),
            posts_count=Count(
                "posts",
                filter=models.Q(posts__status=Post.APPROVED)
                | models.Q(posts__status=getattr(Post, "PENDING_REAPPROVAL", Post.PENDING)),
                distinct=True,
            ),
        )
        user = qs.first()
        if not user:
            return Response({"detail": "Not found"}, status=404)
        data = self.get_serializer(user).data
        return Response(data)


class UserPublicPostsView(_PublicUserQueryMixin, generics.GenericAPIView):
    """Paginated list of public posts for a given user.

    Uses cursor-based pagination on (created_at, id) for stability.
    """

    permission_classes = [IsNormalUser]
    serializer_class = PostSerializer
    PAGE_SIZE_DEFAULT = 20
    PAGE_SIZE_MAX = 50

    def _encode_cursor(self, created_at, last_id: int) -> str:
        import base64, json

        payload = json.dumps(
            {"created_at": created_at.isoformat(), "last_id": last_id}
        ).encode("utf-8")
        return base64.urlsafe_b64encode(payload).decode("ascii")

    def _decode_cursor(self, cursor: str):
        import base64, json
        from datetime import datetime

        try:
            data = base64.urlsafe_b64decode(cursor.encode("ascii"))
            obj = json.loads(data.decode("utf-8"))
            created_at = datetime.fromisoformat(obj["created_at"])
            last_id = int(obj["last_id"])
            return created_at, last_id
        except Exception:
            return None, None

    def get_queryset(self, owner: NormalUser):
        return (
            Post.objects.filter(
                author=owner,
                status__in=[Post.APPROVED, getattr(Post, "PENDING_REAPPROVAL", Post.APPROVED)],
            )
            .annotate(
                like_count=Count(
                    "reactions",
                    filter=models.Q(reactions__reaction_type=PostReaction.REACT_LIKE),
                ),
            )
            .select_related("author")
            .prefetch_related("items")
            .order_by("-created_at", "-id")
        )

    def get_serializer_context(self):
        ctx = super().get_serializer_context()
        ctx["is_public"] = True
        return ctx

    def get(self, request, pk, *args, **kwargs):
        try:
            page_size = int(request.query_params.get("page_size", self.PAGE_SIZE_DEFAULT))
        except Exception:
            page_size = self.PAGE_SIZE_DEFAULT
        page_size = max(1, min(self.PAGE_SIZE_MAX, page_size))

        # Reuse the same visibility and block rules as discovery/search.
        owner = self._base_public_qs(request).filter(pk=pk).first()
        if not owner:
            return Response({"results": [], "next_cursor": None}, status=404)

        cursor = request.query_params.get("cursor")
        qs = self.get_queryset(owner)

        if cursor:
            created_at, last_id = self._decode_cursor(cursor)
            if created_at is None or last_id is None:
                return Response({"detail": "Invalid cursor"}, status=400)
            qs = qs.filter(
                models.Q(created_at__lt=created_at)
                | (models.Q(created_at=created_at) & models.Q(id__lt=last_id))
            )

        posts = list(qs[:page_size])
        if not posts:
            return Response({"results": [], "next_cursor": None})

        data = self.get_serializer(posts, many=True).data
        last = posts[-1]
        next_cursor = (
            self._encode_cursor(last.created_at, last.id)
            if len(posts) == page_size
            else None
        )
        return Response({"results": data, "next_cursor": next_cursor})


class SubmitFeedbackView(generics.CreateAPIView):
    permission_classes = [IsNormalUser]
    serializer_class = FeedbackSerializer

    def create(self, request, *args, **kwargs):
        # Expect: post_id, content
        post_id = request.data.get("post_id")
        content = (request.data.get("content") or "").strip()
        if not post_id:
            return Response({"detail": "post_id is required"}, status=400)
        post = get_object_or_404(Post, pk=post_id)
        serializer = self.get_serializer(data={"content": content})
        serializer.is_valid(raise_exception=True)
        instance = serializer.save(post=post)
        # Do NOT award here; coins for comments are granted only after admin approval.
        headers = self.get_success_headers(serializer.data)
        return Response(FeedbackSerializer(instance).data, status=201, headers=headers)

    def _award_reward(self, user, post, action):
        from django.conf import settings
        from django.utils import timezone
        from django.db import transaction
        from django.db.models import F
        # Values: VIEW_TOKENS, LIKE_TOKENS, COMMENT_TOKENS
        tokens_table = {
            RewardTransaction.ACT_VIEW: getattr(settings, "REWARD_VIEW_TOKENS", 1),
            RewardTransaction.ACT_LIKE: getattr(settings, "REWARD_LIKE_TOKENS", 2),
            RewardTransaction.ACT_COMMENT: getattr(settings, "REWARD_COMMENT_TOKENS", 5),
        }
        # Daily limits per action
        limits_table = {
            RewardTransaction.ACT_VIEW: getattr(settings, "REWARD_VIEW_DAILY_LIMIT", 50),
            RewardTransaction.ACT_LIKE: getattr(settings, "REWARD_LIKE_DAILY_LIMIT", 20),
            RewardTransaction.ACT_COMMENT: getattr(settings, "REWARD_COMMENT_DAILY_LIMIT", 10),
        }
        tval = tokens_table.get(action, 0)
        # Enforce per-user daily limit per action across posts
        start_of_day = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
        awarded_today = RewardTransaction.objects.filter(user=user, action_type=action, created_at__gte=start_of_day).count()
        if awarded_today >= limits_table.get(action, 0):
            return
        # Prevent duplicates per user/post/action via unique_together
        with transaction.atomic():
            obj, created = RewardTransaction.objects.get_or_create(
                user=user,
                post=post,
                action_type=action,
                defaults={"tokens": tval},
            )
            if created and tval > 0:
                bal, _ = UserTokenBalance.objects.select_for_update().get_or_create(user=user, defaults={"balance": 0})
                bal.balance = F("balance") + tval
                bal.save(update_fields=["balance", "updated_at"])


class AdminPendingFeedbackListView(generics.ListAPIView):
    permission_classes = [IsAdminEnabled]
    serializer_class = FeedbackSerializer

    def get_queryset(self):
        return Feedback.objects.filter(status=Feedback.STATUS_PENDING).order_by("-created_at", "-id")

class AdminApprovedFeedbackListView(generics.ListAPIView):
    permission_classes = [IsAdminEnabled]
    serializer_class = FeedbackSerializer

    def get_queryset(self):
        return Feedback.objects.filter(status=Feedback.STATUS_APPROVED).order_by("-created_at", "-id")

class AdminRejectedFeedbackListView(generics.ListAPIView):
    permission_classes = [IsAdminEnabled]
    serializer_class = FeedbackSerializer

    def get_queryset(self):
        return Feedback.objects.filter(status=Feedback.STATUS_REJECTED).order_by("-created_at", "-id")


class AdminApproveFeedbackView(generics.GenericAPIView):
    permission_classes = [IsAdminEnabled]

    def post(self, request, pk, *args, **kwargs):
        fb = get_object_or_404(Feedback, pk=pk)
        if fb.status != Feedback.STATUS_PENDING:
            return Response({"detail": "Feedback not pending"}, status=400)
        fb.status = Feedback.STATUS_APPROVED
        fb.save(update_fields=["status"])
        # Award comment reward once per user/post on approval, only for admin/superadmin posts
        try:
            post = fb.post
            user = fb.author
            role = getattr(post, "created_by_role", None)
            if getattr(post, "admin_author_id", None) or role in ("admin", "superadmin"):
                # Enforce idempotency: only first approved comment per user/post grants coins
                from django.conf import settings
                from django.db import transaction, IntegrityError
                from django.db.models import F
                tval = getattr(settings, "REWARD_COMMENT_TOKENS", 30)
                # Fast path: skip if a comment reward already exists
                exists = RewardTransaction.objects.filter(
                    user=user,
                    post=post,
                    action_type=RewardTransaction.ACT_COMMENT,
                ).exists()
                if not exists:
                    try:
                        with transaction.atomic():
                            obj, created = RewardTransaction.objects.get_or_create(
                                user=user,
                                post=post,
                                action_type=RewardTransaction.ACT_COMMENT,
                                defaults={"tokens": tval},
                            )
                            if created and tval > 0:
                                bal, _ = UserTokenBalance.objects.select_for_update().get_or_create(user=user, defaults={"balance": 0})
                                bal.balance = F("balance") + tval
                                bal.save(update_fields=["balance", "updated_at"])
                    except IntegrityError:
                        # Another concurrent approval created the reward; do nothing
                        pass
        except Exception:
            pass
        # Optional: notify post author via email
        author = getattr(getattr(fb.post, "author", None), "email", None)
        if author:
            try:
                email_send("New feedback approved", f"Someone left feedback on your post: {fb.content}", author)
            except Exception:
                pass
        return Response(FeedbackSerializer(fb).data)


class AdminRejectFeedbackView(generics.GenericAPIView):
    permission_classes = [IsAdminEnabled]

    def post(self, request, pk, *args, **kwargs):
        fb = get_object_or_404(Feedback, pk=pk)
        if fb.status != Feedback.STATUS_PENDING:
            return Response({"detail": "Feedback not pending"}, status=400)
        fb.status = Feedback.STATUS_REJECTED
        fb.save(update_fields=["status"])
        # Optional: notify feedback author via email with provided reason
        try:
            reason = (request.data.get("reason") or "").strip()
        except Exception:
            reason = ""
        author_email = getattr(getattr(fb, "author", None), "email", None)
        if author_email:
            try:
                subject = "Your feedback was rejected"
                body = (
                    f"Your feedback on Post #{fb.post_id} has been rejected by an admin."
                    + (f" Reason: {reason}" if reason else "")
                )
                email_send(subject, body, author_email)
            except Exception:
                pass
        return Response(FeedbackSerializer(fb).data)


class PublicApprovedFeedbackByPostView(generics.ListAPIView):
    """Public: list approved feedback for a given post.
    Visible when a user views a public post.
    """
    permission_classes = [AllowAny]
    serializer_class = FeedbackSerializer

    def get_queryset(self):
        pk = self.kwargs.get("pk")
        post = get_object_or_404(Post, pk=pk)
        # Only allow for public/approved posts (or pending re-approval snapshot)
        if post.status not in (Post.APPROVED, getattr(Post, "PENDING_REAPPROVAL", Post.APPROVED)):
            return Feedback.objects.none()
        return Feedback.objects.filter(post_id=post.id, status=Feedback.STATUS_APPROVED).order_by("-created_at", "-id")


class MyRejectedFeedbackListView(generics.ListAPIView):
    """Normal user: list my rejected feedback entries."""
    permission_classes = [IsNormalUser]
    serializer_class = FeedbackSerializer

    def get_queryset(self):
        user = getattr(self.request.user, "normal_user", None)
        if not user:
            return Feedback.objects.none()
        return Feedback.objects.filter(author=user, status=Feedback.STATUS_REJECTED).order_by("-created_at", "-id")


class EditRejectedFeedbackView(generics.GenericAPIView):
    """Normal user: edit a rejected feedback to resubmit for review.
    Allows changing content and resets status to PENDING.
    """
    permission_classes = [IsNormalUser]

    def patch(self, request, pk, *args, **kwargs):
        return self._update(request, pk)

    def put(self, request, pk, *args, **kwargs):
        return self._update(request, pk)

    def _update(self, request, pk):
        fb = get_object_or_404(Feedback, pk=pk)
        user = getattr(request.user, "normal_user", None)
        if not user or fb.author_id != getattr(user, "id", None):
            return Response({"detail": "Not allowed"}, status=403)
        if fb.status != Feedback.STATUS_REJECTED:
            return Response({"detail": "Only rejected feedback can be edited"}, status=400)
        content = (request.data.get("content") or "").strip()
        if not content:
            return Response({"detail": "Content is required"}, status=400)
        if len(content) > 3000:
            return Response({"detail": "Content exceeds 3000 characters"}, status=400)
        fb.content = content
        fb.status = Feedback.STATUS_PENDING
        fb.save(update_fields=["content", "status"])
        return Response(FeedbackSerializer(fb).data)


class PostCommentListCreateView(generics.GenericAPIView):
    """List and create top-level comments for a post.

    GET  /posts/{id}/comments   -> paginated top-level comments
    POST /posts/{id}/comments   -> create a top-level comment
    """

    permission_classes = [AllowAny]

    def get(self, request, pk, *args, **kwargs):
        post = get_object_or_404(Post, pk=pk)
        qs = get_top_level_comments_queryset(post)
        page_size = int(request.query_params.get("page_size", 20))
        page = int(request.query_params.get("page", 1))
        if page < 1:
            page = 1
        offset = (page - 1) * page_size
        items = list(qs[offset : offset + page_size])
        data = CommentSerializer(items, many=True).data
        return Response({
            "results": data,
            "page": page,
            "page_size": page_size,
        })

    def post(self, request, pk, *args, **kwargs):
        if not IsNormalUser().has_permission(request, self):
            return Response({"detail": "Authentication required"}, status=401)
        post = get_object_or_404(Post, pk=pk)
        serializer = CommentCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        content = serializer.validated_data.get("content")
        user = request.user.normal_user
        try:
            result = create_comment(user=user, post=post, content=content, parent=None)
        except ValueError as e:
            return Response({"detail": str(e)}, status=400)
        return Response(CommentSerializer(result.comment).data, status=201)


class CommentReplyListCreateView(generics.GenericAPIView):
    """List and create direct replies for a given comment.

    GET  /comments/{id}/replies  -> paginated direct replies
    POST /comments/{id}/replies  -> create a reply
    """

    permission_classes = [AllowAny]

    def get(self, request, pk, *args, **kwargs):
        parent = get_object_or_404(Comment, pk=pk)
        qs = get_replies_queryset(parent)
        page_size = int(request.query_params.get("page_size", 20))
        page = int(request.query_params.get("page", 1))
        if page < 1:
            page = 1
        offset = (page - 1) * page_size
        items = list(qs[offset : offset + page_size])
        data = CommentSerializer(items, many=True).data
        return Response({
            "results": data,
            "page": page,
            "page_size": page_size,
        })

    def post(self, request, pk, *args, **kwargs):
        if not IsNormalUser().has_permission(request, self):
            return Response({"detail": "Authentication required"}, status=401)
        parent = get_object_or_404(Comment, pk=pk)
        serializer = CommentCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        content = serializer.validated_data.get("content")
        user = request.user.normal_user
        try:
            result = create_comment(user=user, post=parent.post, content=content, parent=parent)
        except ValueError as e:
            return Response({"detail": str(e)}, status=400)
        return Response(CommentSerializer(result.comment).data, status=201)


class CommentDetailView(generics.GenericAPIView):
    """Edit or soft-delete a single comment.

    PATCH /comments/{id}  -> edit
    DELETE /comments/{id} -> soft delete
    """

    permission_classes = [IsNormalUser]

    def patch(self, request, pk, *args, **kwargs):
        comment = get_object_or_404(Comment, pk=pk)
        user = request.user.normal_user
        serializer = CommentCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        content = serializer.validated_data.get("content")
        try:
            updated = edit_comment(user=user, comment=comment, content=content)
        except PermissionError as e:
            return Response({"detail": str(e)}, status=403)
        except ValueError as e:
            return Response({"detail": str(e)}, status=400)
        return Response(CommentSerializer(updated).data)

    def delete(self, request, pk, *args, **kwargs):
        comment = get_object_or_404(Comment, pk=pk)
        user = request.user.normal_user
        try:
            deleted = soft_delete_comment(user=user, comment=comment)
        except PermissionError as e:
            return Response({"detail": str(e)}, status=403)
        return Response(CommentSerializer(deleted).data, status=200)


class ToggleLikeView(generics.GenericAPIView):
    """Normal user toggles like on a post; reward like on admin-authored posts.
    """
    permission_classes = [IsNormalUser]

    def post(self, request, *args, **kwargs):
        post_id = request.data.get("post_id")
        if not post_id:
            return Response({"detail": "post_id is required"}, status=400)
        post = get_object_or_404(Post, pk=post_id)
        user = request.user.normal_user
        react, created = PostReaction.objects.get_or_create(user=user, post=post, reaction_type=PostReaction.REACT_LIKE)
        if not created:
            react.delete()
            # If there was a like reward for this user/post, revoke it
            try:
                role = getattr(post, "created_by_role", None)
                if getattr(post, "admin_author_id", None) or role in ("admin", "superadmin"):
                    from django.conf import settings
                    from django.db import transaction
                    from django.db.models import F
                    tval = getattr(settings, "REWARD_LIKE_TOKENS", 20)
                    with transaction.atomic():
                        txn = RewardTransaction.objects.filter(user=user, post=post, action_type=RewardTransaction.ACT_LIKE).first()
                        if txn:
                            # Delete transaction and subtract tokens
                            txn.delete()
                            bal, _ = UserTokenBalance.objects.select_for_update().get_or_create(user=user, defaults={"balance": 0})
                            # Prevent negative balance
                            bal.balance = F("balance") - tval
                            bal.save(update_fields=["balance", "updated_at"])
            except Exception:
                pass
            return Response({"liked": False})
        # Award like reward once (unique per action enforced by RewardTransaction)
        try:
            role = getattr(post, "created_by_role", None)
            if getattr(post, "admin_author_id", None) or role in ("admin", "superadmin"):
                self._award_reward(user=user, post=post, action=RewardTransaction.ACT_LIKE)
        except Exception:
            pass
        return Response({"liked": True})

    def _award_reward(self, user, post, action):
        from django.conf import settings
        from django.utils import timezone
        from django.db import transaction
        from django.db.models import F
        tokens_table = {
            RewardTransaction.ACT_VIEW: getattr(settings, "REWARD_VIEW_TOKENS", 1),
            RewardTransaction.ACT_LIKE: getattr(settings, "REWARD_LIKE_TOKENS", 2),
            RewardTransaction.ACT_COMMENT: getattr(settings, "REWARD_COMMENT_TOKENS", 5),
        }
        limits_table = {
            RewardTransaction.ACT_VIEW: getattr(settings, "REWARD_VIEW_DAILY_LIMIT", 50),
            RewardTransaction.ACT_LIKE: getattr(settings, "REWARD_LIKE_DAILY_LIMIT", 20),
            RewardTransaction.ACT_COMMENT: getattr(settings, "REWARD_COMMENT_DAILY_LIMIT", 10),
        }
        tval = tokens_table.get(action, 0)
        start_of_day = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
        awarded_today = RewardTransaction.objects.filter(user=user, action_type=action, created_at__gte=start_of_day).count()
        if awarded_today >= limits_table.get(action, 0):
            return
        with transaction.atomic():
            obj, created = RewardTransaction.objects.get_or_create(
                user=user,
                post=post,
                action_type=action,
                defaults={"tokens": tval},
            )
            if created and tval > 0:
                bal, _ = UserTokenBalance.objects.select_for_update().get_or_create(user=user, defaults={"balance": 0})
                bal.balance = F("balance") + tval
                bal.save(update_fields=["balance", "updated_at"])


class RecordViewRewardView(generics.GenericAPIView):
    """Record a view of a post and award tokens one-time if admin-authored."""
    permission_classes = [IsNormalUser]

    def post(self, request, *args, **kwargs):
        post_id = request.data.get("post_id")
        if not post_id:
            return Response({"detail": "post_id is required"}, status=400)
        post = get_object_or_404(Post, pk=post_id)
        user = request.user.normal_user
        # Increment the post's view counter only the first time this user views it.
        # PostView ensures uniqueness per user/post; using F() keeps the update atomic.
        from django.db import transaction
        from django.db.models import F
        view_recorded = False
        with transaction.atomic():
            pv, created = PostView.objects.get_or_create(user=user, post=post)
            if created:
                Post.objects.filter(pk=post.pk).update(view_count=F("view_count") + 1)
                view_recorded = True
        post.refresh_from_db(fields=["view_count"])
        awarded = False
        tokens_awarded = 0
        try:
            role = getattr(post, "created_by_role", None)
            if getattr(post, "admin_author_id", None) or role in ("admin", "superadmin"):
                tokens_awarded = self._award_reward(user=user, post=post, action=RewardTransaction.ACT_VIEW)
                awarded = tokens_awarded > 0
        except Exception:
            pass
        return Response({
            "view_recorded": view_recorded,
            "awarded": awarded,
            "tokens": tokens_awarded,
            "view_count": post.view_count,
        })

    def _award_reward(self, user, post, action):
        from django.conf import settings
        from django.utils import timezone
        from django.db import transaction
        from django.db.models import F
        tokens_table = {
            RewardTransaction.ACT_VIEW: getattr(settings, "REWARD_VIEW_TOKENS", 1),
            RewardTransaction.ACT_LIKE: getattr(settings, "REWARD_LIKE_TOKENS", 2),
            RewardTransaction.ACT_COMMENT: getattr(settings, "REWARD_COMMENT_TOKENS", 5),
        }
        limits_table = {
            RewardTransaction.ACT_VIEW: getattr(settings, "REWARD_VIEW_DAILY_LIMIT", 50),
            RewardTransaction.ACT_LIKE: getattr(settings, "REWARD_LIKE_DAILY_LIMIT", 20),
            RewardTransaction.ACT_COMMENT: getattr(settings, "REWARD_COMMENT_DAILY_LIMIT", 10),
        }
        tval = tokens_table.get(action, 0)
        start_of_day = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
        awarded_today = RewardTransaction.objects.filter(user=user, action_type=action, created_at__gte=start_of_day).count()
        if awarded_today >= limits_table.get(action, 0):
            return 0
        with transaction.atomic():
            obj, created = RewardTransaction.objects.get_or_create(
                user=user,
                post=post,
                action_type=action,
                defaults={"tokens": tval},
            )
            if created and tval > 0:
                bal, _ = UserTokenBalance.objects.select_for_update().get_or_create(user=user, defaults={"balance": 0})
                bal.balance = F("balance") + tval
                bal.save(update_fields=["balance", "updated_at"])
                return tval
        return 0

class MeTokenBalanceView(generics.GenericAPIView):
    """Return the current user's token balance."""
    permission_classes = [IsNormalUser]

    def get(self, request, *args, **kwargs):
        user = request.user.normal_user
        bal, _ = UserTokenBalance.objects.get_or_create(user=user)
        return Response({"balance": bal.balance})


class MeRewardHistoryView(generics.ListAPIView):
    """List the current user's reward transactions with post info."""
    permission_classes = [IsNormalUser]
    serializer_class = RewardTransactionSerializer

    def get_queryset(self):
        user = getattr(self.request.user, "normal_user", None)
        if not user:
            return RewardTransaction.objects.none()
        return RewardTransaction.objects.filter(user=user).order_by("-created_at", "-id")
