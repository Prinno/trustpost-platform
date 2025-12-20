from django.contrib.auth.hashers import check_password, make_password
from django.utils import timezone
from rest_framework import serializers

from .models import NormalUser, VerificationToken, PhoneOTP, RefreshToken, PendingRegistration, PasswordResetOTP, PasswordResetSession, Post, PostItem, ModerationAction, UserRestriction


class NormalUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = NormalUser
        fields = [
            "id",
            "username",
            "public_username",
            "email",
            "phone",
            "avatar_url",
            "is_active",
            "is_email_verified",
            "is_phone_verified",
            "created_at",
        ]


class NormalUserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = NormalUser
        fields = [
            "username",
            "phone",
            "public_username",
            "avatar_url",
        ]

    def validate_username(self, value):
        if not value:
            return value
        qs = NormalUser.objects.filter(username__iexact=value)
        if self.instance:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise serializers.ValidationError("Username already exists.")
        return value

    def validate_phone(self, value):
        if not value:
            return value
        qs = NormalUser.objects.filter(phone=value)
        if self.instance:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise serializers.ValidationError("Phone already registered.")
        return value

    def validate_public_username(self, value):
        if not value:
            return value
        qs = NormalUser.objects.filter(public_username__iexact=value)
        if self.instance:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise serializers.ValidationError("Public username already exists.")
        if not value.startswith("@"):
            value = f"@{value}"
        return value


class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=50)
    email = serializers.EmailField(required=True)
    phone = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, min_length=8)

    def validate(self, attrs):
        username = attrs.get("username", "").strip()
        email = attrs.get("email")
        phone = attrs.get("phone")
        password = attrs.get("password")
        confirm = attrs.get("confirm_password")

        if not username:
            raise serializers.ValidationError("Username is required.")
        if password != confirm:
            raise serializers.ValidationError("Passwords do not match.")

        # Check duplicates only among VERIFIED users (NormalUser table)
        if NormalUser.objects.filter(username__iexact=username).exists():
            raise serializers.ValidationError("Username already exists.")
        if NormalUser.objects.filter(email__iexact=email).exists():
            raise serializers.ValidationError("Email already exists.")
        if phone and NormalUser.objects.filter(phone=phone).exists():
            raise serializers.ValidationError("Phone already registered.")

        return attrs

    def create(self, validated_data):
        # Do NOT create NormalUser here.
        from django.conf import settings
        from datetime import timedelta
        from .utils import generate_token, now_utc

        password_plain = validated_data.pop("password")
        validated_data.pop("confirm_password", None)
        password_hashed = make_password(password_plain)

        token = generate_token()
        expires = now_utc() + timedelta(hours=getattr(settings, "NORMAL_USER_VERIFY_TOKEN_HOURS", 24))

        pending = PendingRegistration.objects.create(
            password=password_hashed,
            token=token,
            expires_at=expires,
            used=False,
            **validated_data,
        )
        return pending


class LoginSerializer(serializers.Serializer):
    identifier = serializers.CharField()
    password = serializers.CharField(write_only=True)

    # Do not perform user lookup here; handled in view for unified flow
    def validate(self, attrs):
        if not attrs.get("identifier") or not attrs.get("password"):
            raise serializers.ValidationError("identifier and password are required")
        return attrs


class RequestEmailVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, attrs):
        email = attrs["email"]
        try:
            user = NormalUser.objects.get(email=email)
        except NormalUser.DoesNotExist:
            raise serializers.ValidationError("No account with this email.")
        attrs["user"] = user
        return attrs


class VerifyEmailSerializer(serializers.Serializer):
    token = serializers.CharField()


class RequestPhoneOTPSerializer(serializers.Serializer):
    phone = serializers.CharField()

    def validate(self, attrs):
        phone = attrs["phone"]
        try:
            user = NormalUser.objects.get(phone=phone)
        except NormalUser.DoesNotExist:
            raise serializers.ValidationError("No account with this phone.")
        attrs["user"] = user
        return attrs


class VerifyPhoneOTPSerializer(serializers.Serializer):
    phone = serializers.CharField()
    code = serializers.CharField(max_length=6)


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, attrs):
        # Do not reveal whether account exists; attach user if found
        email = attrs.get("email")
        user = NormalUser.objects.filter(email__iexact=email).first()
        attrs["user"] = user  # may be None
        return attrs


class PasswordResetOTPVerifySerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)


class PasswordResetConfirmSerializer(serializers.Serializer):
    reset_token = serializers.CharField()
    new_password = serializers.CharField(min_length=8)
    confirm_password = serializers.CharField(min_length=8)

    def validate(self, attrs):
        if attrs.get("new_password") != attrs.get("confirm_password"):
            raise serializers.ValidationError("Passwords do not match.")
        return attrs


class PostItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = PostItem
        fields = [
            "id",
            "media_type",
            "file_url",
            "caption_text",
            "order",
        ]


class PostSerializer(serializers.ModelSerializer):
    items = PostItemSerializer(many=True, required=False)

    class Meta:
        model = Post
        fields = [
            "id",
            "author",
            "mode",
            "main_text",
            "status",
            "rejection_reason",
            "created_at",
            "updated_at",
            "items",
        ]
        read_only_fields = ["author", "status", "rejection_reason", "created_at", "updated_at"]

    def validate(self, attrs):
        mode = attrs.get("mode")
        main_text = (attrs.get("main_text") or "").strip()
        items = self.initial_data.get("items")
        if items is None:
            items = attrs.get("items", [])

        if mode not in {
            Post.TEXT_ONLY,
            Post.SINGLE_WITH_TEXT,
            Post.MULTI_SHARED,
            Post.MULTI_PER_TEXT,
        }:
            raise serializers.ValidationError("Invalid mode")

        if len(main_text) > 3000:
            raise serializers.ValidationError("Main text exceeds 3000 characters")

        # A: Text only
        if mode == Post.TEXT_ONLY:
            if not main_text:
                raise serializers.ValidationError("Main text is required for text-only posts")
            if items:
                raise serializers.ValidationError("Text-only posts must have no media items")

        # B: Single media + text
        if mode == Post.SINGLE_WITH_TEXT:
            if not main_text:
                raise serializers.ValidationError("Main text is required for single media mode")
            if not isinstance(items, list) or len(items) != 1:
                raise serializers.ValidationError("Single media mode requires exactly one media item")

        # D: Multiple media + shared text
        if mode == Post.MULTI_SHARED:
            if not main_text:
                raise serializers.ValidationError("Shared text is required for multiple media shared mode")
            if not isinstance(items, list) or len(items) < 2:
                raise serializers.ValidationError("Shared mode requires two or more media items")

        # C: Multiple media, each with text (no main text)
        if mode == Post.MULTI_PER_TEXT:
            if main_text:
                raise serializers.ValidationError("Main text must be empty in per-media text mode")
            if not isinstance(items, list) or len(items) < 2:
                raise serializers.ValidationError("Per-media mode requires two or more media items")
            for idx, it in enumerate(items or []):
                caption = (it.get("caption_text") or "").strip()
                if not caption:
                    raise serializers.ValidationError(f"Caption required for item #{idx + 1}")
                if len(caption) > 3000:
                    raise serializers.ValidationError(f"Caption for item #{idx + 1} exceeds 3000 characters")

        return attrs

    def create(self, validated_data):
        items_data = validated_data.pop("items", [])
        request = self.context.get("request")
        author = getattr(getattr(request, "user", None), "normal_user", None)
        if not author:
            raise serializers.ValidationError("Invalid author")
        # Enforce posting restrictions
        active_post_bans = UserRestriction.objects.filter(user=author, type=UserRestriction.TYPE_POST_SUSPEND).all()
        for r in active_post_bans:
            if r.is_active():
                raise serializers.ValidationError("Posting is temporarily disabled for your account")
        post = Post.objects.create(author=author, status=Post.PENDING, **validated_data)
        for order, item in enumerate(items_data):
            PostItem.objects.create(
                post=post,
                media_type=item.get("media_type"),
                file_url=item.get("file_url"),
                caption_text=item.get("caption_text", "") or "",
                order=item.get("order", order),
            )
        return post


class ModerationActionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ModerationAction
        fields = [
            "id",
            "post",
            "actor_username",
            "actor_role",
            "action",
            "reason",
            "created_at",
        ]


class UserRestrictionSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRestriction
        fields = [
            "id",
            "user",
            "type",
            "reason",
            "until",
            "created_by",
            "created_at",
        ]
