from django.contrib.auth.hashers import check_password, make_password
from django.utils import timezone
from rest_framework import serializers

from .models import NormalUser, VerificationToken, PhoneOTP, RefreshToken, PendingRegistration, PasswordResetOTP, PasswordResetSession, Post, PostItem, ModerationAction, UserRestriction, Feedback, RewardTransaction, PostReaction, Comment, PostVersion, AdReview
import json


class NormalUserSerializer(serializers.ModelSerializer):
    avatar_url = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = NormalUser
        fields = [
            "id",
            "username",
            "public_username",
            "organization_name",
            "email",
            "phone",
            "avatar_url",
            "account_type",
            "status",
            "is_active",
            "is_email_verified",
            "is_phone_verified",
            "created_at",
        ]

    def get_avatar_url(self, obj):
        # Always return a relative media path for avatar
        try:
            from .utils import normalize_media_url
            return normalize_media_url(getattr(obj, "avatar_url", None))
        except Exception:
            return getattr(obj, "avatar_url", None)


class AdminAdvertiserSerializer(serializers.ModelSerializer):
    class Meta:
        model = NormalUser
        fields = [
            "id",
            "username",
            "email",
            "phone",
            "account_type",
            "status",
            "organization_name",
            "organization_email",
            "phone_number",
            "created_at",
        ]


class PublicUserSerializer(serializers.ModelSerializer):
    avatar_url = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = NormalUser
        fields = [
            "id",
            "username",
            "public_username",
            "avatar_url",
        ]

    def get_avatar_url(self, obj):
        try:
            from .utils import normalize_media_url
            return normalize_media_url(getattr(obj, "avatar_url", None))
        except Exception:
            return getattr(obj, "avatar_url", None)


class UserSearchResultSerializer(serializers.ModelSerializer):
    """Lightweight user representation for search/discovery lists.

    Exposes only public profile fields and pre-annotated follower counts.
    """

    avatar_url = serializers.SerializerMethodField(read_only=True)
    bio_short = serializers.SerializerMethodField(read_only=True)
    followers_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = NormalUser
        fields = [
            "id",
            "username",
            "public_username",
            "avatar_url",
            "bio_short",
            "followers_count",
        ]

    def get_avatar_url(self, obj):
        try:
            from .utils import normalize_media_url
            return normalize_media_url(getattr(obj, "avatar_url", None))
        except Exception:
            return getattr(obj, "avatar_url", None)

    def get_bio_short(self, obj):
        bio = (getattr(obj, "bio", "") or "").strip()
        if not bio:
            return ""
        return bio if len(bio) <= 120 else bio[:117] + "..."


class UserProfileSerializer(serializers.ModelSerializer):
    """Public profile view for another user.

    Follower/following/posts counts are expected to be annotated in the
    queryset for performance, but we fall back to on-demand counts if
    they are missing (e.g., in tests).
    """

    avatar_url = serializers.SerializerMethodField(read_only=True)
    followers_count = serializers.IntegerField(read_only=True)
    following_count = serializers.IntegerField(read_only=True)
    posts_count = serializers.IntegerField(read_only=True)
    joined_date = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = NormalUser
        fields = [
            "id",
            "username",
            "public_username",
            "full_name",
            "bio",
            "avatar_url",
            "followers_count",
            "following_count",
            "posts_count",
            "joined_date",
        ]

    def get_avatar_url(self, obj):
        try:
            from .utils import normalize_media_url
            return normalize_media_url(getattr(obj, "avatar_url", None))
        except Exception:
            return getattr(obj, "avatar_url", None)

    def get_joined_date(self, obj):
        dt = getattr(obj, "created_at", None)
        if not dt:
            return None
        try:
            return dt.date().isoformat()
        except Exception:
            return None


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

    def validate_avatar_url(self, value):
        # Accept any form but store relative media path only
        try:
            from .utils import normalize_media_url
            return normalize_media_url(value)
        except Exception:
            return value


class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=50)
    email = serializers.EmailField(required=True)
    phone = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, min_length=8)
    account_type = serializers.ChoiceField(
        choices=[NormalUser.ACCOUNT_TYPE_PERSON, NormalUser.ACCOUNT_TYPE_ADVERTISER],
        default=NormalUser.ACCOUNT_TYPE_PERSON,
    )
    organization_name = serializers.CharField(required=False, allow_blank=True, allow_null=True, max_length=255)
    organization_email = serializers.EmailField(required=False, allow_blank=True, allow_null=True)
    phone_number = serializers.CharField(required=False, allow_blank=True, allow_null=True, max_length=20)

    def validate(self, attrs):
        username = attrs.get("username", "").strip()
        email = attrs.get("email")
        phone = attrs.get("phone")
        password = attrs.get("password")
        confirm = attrs.get("confirm_password")
        account_type = attrs.get("account_type") or NormalUser.ACCOUNT_TYPE_PERSON
        org_name = attrs.get("organization_name")
        org_email = attrs.get("organization_email")
        org_phone_number = attrs.get("phone_number")

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

        # Additional validation for advertiser accounts
        if account_type == NormalUser.ACCOUNT_TYPE_ADVERTISER:
            if not org_name or not org_name.strip():
                raise serializers.ValidationError("Organization/Business name is required for advertiser accounts.")
            # Do not require a second email/phone field; reuse main ones if needed.
            if not (phone or org_phone_number):
                raise serializers.ValidationError("A phone number is required for advertiser accounts.")

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
    file_url = serializers.SerializerMethodField(read_only=True)
    class Meta:
        model = PostItem
        fields = [
            "id",
            "media_type",
            "file_url",
            "caption_text",
            "order",
        ]

    def get_file_url(self, obj):
        # Ensure file_url is always a relative media path
        try:
            from .utils import normalize_media_url
            return normalize_media_url(getattr(obj, "file_url", None))
        except Exception:
            return getattr(obj, "file_url", None)


class PostSerializer(serializers.ModelSerializer):
    items = PostItemSerializer(many=True, required=False)
    author_public_username = serializers.SerializerMethodField(read_only=True)
    author_full_name = serializers.SerializerMethodField(read_only=True)
    author_avatar_url = serializers.SerializerMethodField(read_only=True)
    author_role = serializers.SerializerMethodField(read_only=True)
    is_liked_by_user = serializers.SerializerMethodField(read_only=True)
    view_count = serializers.IntegerField(read_only=True)
    like_count = serializers.IntegerField(read_only=True)
    comment_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = Post
        fields = [
            "id",
            "author",
            "author_public_username",
            "author_full_name",
            "author_avatar_url",
            "author_role",
            "is_liked_by_user",
            "view_count",
            "mode",
            "main_text",
            "status",
            "rejection_reason",
            "created_at",
            "updated_at",
            "items",
            "like_count",
            "comment_count",
        ]
        read_only_fields = ["author", "status", "rejection_reason", "created_at", "updated_at"]

    def get_author_public_username(self, obj):
        pu = getattr(getattr(obj, "author", None), "public_username", None)
        # Only expose public handle if present
        return pu if pu else None

    def get_author_full_name(self, obj):
        """Return the public display name for the author.

        For advertiser accounts, prefer organization_name as the public name.
        Otherwise, fall back to full_name or username.
        """
        author = getattr(obj, "author", None)
        if not author:
            return None
        # Advertiser: organization/business name takes priority
        try:
            if getattr(author, "account_type", None) == NormalUser.ACCOUNT_TYPE_ADVERTISER:
                org = getattr(author, "organization_name", None)
                if org:
                    return org
        except Exception:
            pass

        full_name = getattr(author, "full_name", None)
        if full_name:
            return full_name
        username = getattr(author, "username", None)
        return username if username else None

    def get_author_avatar_url(self, obj):
        # For admin-authored posts, no avatar is defined here
        try:
            from .utils import normalize_media_url
            return normalize_media_url(getattr(getattr(obj, "author", None), "avatar_url", None))
        except Exception:
            return getattr(getattr(obj, "author", None), "avatar_url", None)

    def get_author_role(self, obj):
        try:
            if getattr(obj, "author", None):
                return "normal"
            acc = getattr(obj, "admin_author", None)
            if acc:
                return getattr(acc, "role", None) or getattr(obj, "created_by_role", None)
        except Exception:
            pass
        return getattr(obj, "created_by_role", None)

    def get_is_liked_by_user(self, obj):
        try:
            request = self.context.get("request")
            user = getattr(getattr(request, "user", None), "normal_user", None)
            if not user:
                return False
            return PostReaction.objects.filter(user=user, post=obj, reaction_type=PostReaction.REACT_LIKE).exists()
        except Exception:
            return False

    def to_representation(self, instance):
        """
        For public views: if post is pending re-approval, present the last approved snapshot
        so public users see only approved content.
        """
        data = super().to_representation(instance)
        is_public = self.context.get("is_public")
        try:
            if is_public and instance.status == Post.PENDING_REAPPROVAL and instance.last_approved_version:
                pv = PostVersion.objects.filter(post=instance, version=instance.last_approved_version, status=PostVersion.STATUS_APPROVED).first()
                if pv:
                    data["main_text"] = pv.main_text or ""
                    # Replace items with snapshot
                    items = []
                    try:
                        snap = json.loads(pv.items_json or "[]")
                        for it in snap:
                            # Normalize snapshot file_url to relative path
                            from .utils import normalize_media_url
                            items.append({
                                "id": None,
                                "media_type": it.get("media_type"),
                                "file_url": normalize_media_url(it.get("file_url")),
                                "caption_text": it.get("caption_text") or "",
                                "order": it.get("order") or 0,
                            })
                    except Exception:
                        items = []
                    data["items"] = items
        except Exception:
            # Fail-safe: leave default representation
            pass
        # Always normalize file_url for items to ensure relative paths
        try:
            from .utils import normalize_media_url
            normd = []
            for it in (data.get("items") or []):
                fu = normalize_media_url(it.get("file_url")) if isinstance(it, dict) else None
                if isinstance(it, dict):
                    it = {**it, "file_url": fu}
                normd.append(it)
            data["items"] = normd
        except Exception:
            pass
        return data

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

        # B: Single media + text (admins may post poster without text)
        if mode == Post.SINGLE_WITH_TEXT:
            # Determine if the requester is an admin/superadmin
            is_admin = False
            try:
                req = self.context.get("request")
                user = getattr(req, "user", None)
                if user is not None:
                    is_admin = bool(getattr(user, "is_staff", False) or getattr(user, "is_superuser", False))
            except Exception:
                is_admin = False
            # For normal users, main_text is required; admins can skip for posters
            if not main_text and not is_admin:
                raise serializers.ValidationError("Main text is required for single media mode")
            if not isinstance(items, list) or len(items) != 1:
                raise serializers.ValidationError("Single media mode requires exactly one media item")

        # D: Multiple media + shared text (admins may post poster set without shared text)
        if mode == Post.MULTI_SHARED:
            # Determine if the requester is an admin/superadmin
            is_admin = False
            try:
                req = self.context.get("request")
                user = getattr(req, "user", None)
                if user is not None:
                    is_admin = bool(getattr(user, "is_staff", False) or getattr(user, "is_superuser", False))
            except Exception:
                is_admin = False
            if not main_text and not is_admin:
                raise serializers.ValidationError("Shared text is required for multiple media shared mode")
            if not isinstance(items, list) or len(items) < 2:
                raise serializers.ValidationError("Shared mode requires two or more media items")

        # C: Multiple media, each with text (no main text)
        if mode == Post.MULTI_PER_TEXT:
            if main_text:
                raise serializers.ValidationError("Main text must be empty in per-media text mode")
            if not isinstance(items, list) or len(items) < 2:
                raise serializers.ValidationError("Per-media mode requires two or more media items")
            # Allow admins to omit per-item captions for poster-style posts
            is_admin = False
            try:
                req = self.context.get("request")
                user = getattr(req, "user", None)
                if user is not None:
                    is_admin = bool(getattr(user, "is_staff", False) or getattr(user, "is_superuser", False))
            except Exception:
                is_admin = False
            for idx, it in enumerate(items or []):
                caption = (it.get("caption_text") or "").strip()
                if not caption and not is_admin:
                    raise serializers.ValidationError(f"Caption required for item #{idx + 1}")
                if len(caption) > 3000:
                    raise serializers.ValidationError(f"Caption for item #{idx + 1} exceeds 3000 characters")

        # Common media validations (for any mode with items)
        if isinstance(items, list) and items:
            for idx, it in enumerate(items):
                mt = (it.get("media_type") or "").strip()
                if mt not in {PostItem.IMAGE, PostItem.VIDEO}:
                    raise serializers.ValidationError(f"Invalid media_type for item #{idx + 1}")
                fu = (it.get("file_url") or "").strip()
                if not fu:
                    raise serializers.ValidationError(f"Missing file_url for item #{idx + 1}")

        return attrs
    
    def create(self, validated_data):
        # Always use raw incoming items to ensure fields like file_url are available
        try:
            items_data = list(self.initial_data.get("items", []))
        except Exception:
            items_data = []
        # Remove any nested items from validated_data to avoid confusion
        validated_data.pop("items", None)
        request = self.context.get("request")
        # Normal user author
        author = getattr(getattr(request, "user", None), "normal_user", None)
        # Admin/SuperAdmin author
        admin_acc = getattr(getattr(request, "user", None), "admin_account", None)
        if author:
            # Enforce posting restrictions for normal users
            active_post_bans = UserRestriction.objects.filter(user=author, type=UserRestriction.TYPE_POST_SUSPEND).all()
            for r in active_post_bans:
                if r.is_active():
                    raise serializers.ValidationError("Posting is temporarily disabled for your account")
            post = Post.objects.create(author=author, status=Post.PENDING, created_by_role="normal", **validated_data)
        elif admin_acc:
            # Admin-created posts default to pending until explicitly published
            role = getattr(admin_acc, "role", "admin")
            post = Post.objects.create(admin_author=admin_acc, status=Post.PENDING, created_by_role=role, **validated_data)
        else:
            # Fallback: allow staff/superuser admins even without AdminAccount row
            user = getattr(request, "user", None)
            if getattr(user, "is_staff", False) or getattr(user, "is_superuser", False):
                role = "superadmin" if getattr(user, "is_superuser", False) else "admin"
                post = Post.objects.create(status=Post.PENDING, created_by_role=role, **validated_data)
            else:
                raise serializers.ValidationError("Invalid author")
        from .utils import normalize_media_url
        for order, item in enumerate(items_data):
            # Normalize and enforce presence of file_url
            norm_url = normalize_media_url(item.get("file_url"))
            if not norm_url:
                raise serializers.ValidationError(f"Invalid media URL for item #{order + 1}")
            PostItem.objects.create(
                post=post,
                media_type=item.get("media_type"),
                # Store only relative media path
                file_url=norm_url,
                caption_text=item.get("caption_text", "") or "",
                order=item.get("order", order),
            )
        return post

class AdReviewSerializer(serializers.ModelSerializer):
    """Serializer for advertiser reviews with public user name."""

    user_public_name = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = AdReview
        fields = [
            "id",
            "rating",
            "comment",
            "created_at",
            "user_public_name",
        ]

    def get_user_public_name(self, obj):
        user = getattr(obj, "user", None)
        if not user:
            return None
        # For advertisers, prefer organization_name; else full_name or username
        try:
            if getattr(user, "account_type", None) == NormalUser.ACCOUNT_TYPE_ADVERTISER:
                org = getattr(user, "organization_name", None)
                if org:
                    return org
        except Exception:
            pass
        full_name = getattr(user, "full_name", None)
        if full_name:
            return full_name
        username = getattr(user, "username", None)
        return username if username else None


class AdvertiserAnalyticsSummarySerializer(serializers.Serializer):
    total_views = serializers.IntegerField()
    total_likes = serializers.IntegerField()
    total_dislikes = serializers.IntegerField()
    total_shares = serializers.IntegerField()
    total_comments = serializers.IntegerField()
    total_gift_tokens = serializers.IntegerField()
    gift_view_tokens = serializers.IntegerField()
    gift_like_tokens = serializers.IntegerField()
    gift_comment_tokens = serializers.IntegerField()
    average_rating = serializers.FloatField(allow_null=True)
    total_reviews = serializers.IntegerField()



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


class CommentSerializer(serializers.ModelSerializer):
    """Serializer for nested comments with minimal embedded user info."""

    user = PublicUserSerializer(read_only=True)
    parent_id = serializers.IntegerField(read_only=True)

    class Meta:
        model = Comment
        fields = [
            "id",
            "content",
            "user",
            "parent_id",
            "reply_count",
            "depth",
            "created_at",
            "is_deleted",
        ]


class CommentCreateSerializer(serializers.Serializer):
    content = serializers.CharField(max_length=3000)



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


class FeedbackSerializer(serializers.ModelSerializer):
    author_username = serializers.SerializerMethodField(read_only=True)
    post_main_text = serializers.SerializerMethodField(read_only=True)
    author_id = serializers.SerializerMethodField(read_only=True)
    post_id = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Feedback
        fields = [
            "id",
            "post_id",
            "author_id",
            "author_username",
            "post_main_text",
            "content",
            "status",
            "created_at",
        ]
        read_only_fields = ["status", "created_at", "author_id", "post_id", "author_username", "post_main_text"]

    def get_author_username(self, obj):
        return getattr(getattr(obj, "author", None), "public_username", None) or getattr(getattr(obj, "author", None), "username", None)

    def get_post_main_text(self, obj):
        return getattr(getattr(obj, "post", None), "main_text", None)

    def get_author_id(self, obj):
        return getattr(getattr(obj, "author", None), "id", None)

    def get_post_id(self, obj):
        return getattr(getattr(obj, "post", None), "id", None)

    def validate(self, attrs):
        content = (attrs.get("content") or "").strip()
        if not content:
            raise serializers.ValidationError("Content is required")
        if len(content) > 3000:
            raise serializers.ValidationError("Content exceeds 3000 characters")
        return attrs

    def create(self, validated_data):
        # Author must be the current normal user
        request = self.context.get("request")
        author = getattr(getattr(request, "user", None), "normal_user", None)
        if not author:
            raise serializers.ValidationError("Invalid author")
        validated_data["author"] = author
        validated_data["status"] = Feedback.STATUS_PENDING
        return super().create(validated_data)


class RewardTransactionSerializer(serializers.ModelSerializer):
    post_id = serializers.SerializerMethodField(read_only=True)
    post_main_text_snippet = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = RewardTransaction
        fields = [
            "id",
            "post_id",
            "action_type",
            "tokens",
            "post_main_text_snippet",
            "created_at",
        ]
        read_only_fields = ["id", "post_id", "action_type", "tokens", "post_main_text_snippet", "created_at"]

    def get_post_id(self, obj):
        return getattr(getattr(obj, "post", None), "id", None)

    def get_post_main_text_snippet(self, obj):
        try:
            txt = getattr(getattr(obj, "post", None), "main_text", "") or ""
            txt = txt.strip()
            if len(txt) <= 80:
                return txt
            return txt[:77] + "..."
        except Exception:
            return None
