from django.db import models
from django.utils import timezone


class NormalUser(models.Model):
    username = models.CharField(max_length=50, unique=True, null=True, blank=True)
    email = models.EmailField(unique=True, null=True, blank=True)
    phone = models.CharField(max_length=20, unique=True, null=True, blank=True)
    public_username = models.CharField(max_length=50, unique=True, null=True, blank=True)
    avatar_url = models.URLField(null=True, blank=True)
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


class PendingRegistration(models.Model):
    """
    Stores registration payload until email verification succeeds.
    No NormalUser row is created at registration time.
    """
    username = models.CharField(max_length=50)
    email = models.EmailField(null=True, blank=True)
    phone = models.CharField(max_length=20, null=True, blank=True)
    password = models.CharField(max_length=255)  # already hashed
    token = models.CharField(max_length=128, unique=True)
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


class PasswordResetOTP(models.Model):
    """
    Email-only password reset OTP.
    - Numeric code (6 digits)
    - Expires after configured minutes
    - Single-use
    """
    email = models.EmailField()
    code = models.CharField(max_length=6)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self) -> bool:
        return (not self.used) and (self.expires_at > timezone.now())


class PasswordResetSession(models.Model):
    """
    Temporary authorization created after successful OTP verification.
    Must be presented to perform password reset.
    """
    email = models.EmailField()
    token = models.CharField(max_length=128, unique=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self) -> bool:
        return (not self.used) and (self.expires_at > timezone.now())


class Post(models.Model):
    TEXT_ONLY = "text_only"
    SINGLE_WITH_TEXT = "single_with_text"
    MULTI_SHARED = "multi_shared"
    MULTI_PER_TEXT = "multi_per_text"
    MODE_CHOICES = (
        (TEXT_ONLY, "Text only"),
        (SINGLE_WITH_TEXT, "Single media with text"),
        (MULTI_SHARED, "Multiple media with shared text"),
        (MULTI_PER_TEXT, "Multiple media each with text"),
    )

    PENDING = "pending"
    PENDING_REAPPROVAL = "pending_reapproval"
    APPROVED = "approved"
    REJECTED = "rejected"
    STATUS_CHOICES = (
        (PENDING, "Pending"),
        (PENDING_REAPPROVAL, "Pending Re-Approval"),
        (APPROVED, "Approved"),
        (REJECTED, "Rejected"),
    )

    # Normal user author (nullable to allow admin-authored posts)
    author = models.ForeignKey(NormalUser, on_delete=models.CASCADE, related_name="posts", null=True, blank=True)
    # Admin/SuperAdmin author
    admin_author = models.ForeignKey("admin_auth.AdminAccount", on_delete=models.SET_NULL, null=True, blank=True, related_name="admin_posts")
    created_by_role = models.CharField(max_length=16, null=True, blank=True, help_text="normal | admin | superadmin")
    mode = models.CharField(max_length=32, choices=MODE_CHOICES)
    main_text = models.TextField(blank=True)
    status = models.CharField(max_length=24, choices=STATUS_CHOICES, default=PENDING)
    rejection_reason = models.TextField(null=True, blank=True)
    last_approved_version = models.PositiveIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        who = self.author_id or self.admin_author_id
        return f"Post#{self.pk} by {who} ({self.mode}/{self.status})"


class PostItem(models.Model):
    IMAGE = "image"
    VIDEO = "video"
    MEDIA_CHOICES = (
        (IMAGE, "Image"),
        (VIDEO, "Video"),
    )

    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="items")
    media_type = models.CharField(max_length=8, choices=MEDIA_CHOICES)
    file_url = models.URLField()
    caption_text = models.TextField(blank=True)
    order = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["order", "id"]

    def __str__(self):
        return f"PostItem#{self.pk} ({self.media_type}) for Post#{self.post_id}"


class PostVersion(models.Model):
    """Immutable snapshot of a Post's content for versioning/rollback."""
    STATUS_PENDING = "pending"
    STATUS_APPROVED = "approved"
    STATUS_REJECTED = "rejected"
    STATUS_CHOICES = (
        (STATUS_PENDING, "Pending"),
        (STATUS_APPROVED, "Approved"),
        (STATUS_REJECTED, "Rejected"),
    )

    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="versions")
    version = models.PositiveIntegerField()
    editor_user = models.ForeignKey(NormalUser, on_delete=models.SET_NULL, null=True, blank=True)
    editor_admin_username = models.CharField(max_length=150, null=True, blank=True)
    editor_role = models.CharField(max_length=16, null=True, blank=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING)
    mode = models.CharField(max_length=32)
    main_text = models.TextField(blank=True)
    items_json = models.TextField(blank=True, help_text="JSON array of item snapshots: media_type, file_url, caption_text, order")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("post", "version")
        ordering = ["-created_at", "-version"]

    def __str__(self):
        return f"PostVersion#{self.version} for Post#{self.post_id} ({self.status})"


class ModerationAction(models.Model):
    """Audit log for content moderation actions."""
    ACTION_APPROVE = "approve"
    ACTION_REJECT = "reject"
    ACTION_EDIT = "edit"
    ACTION_REMOVE = "remove"
    ACTION_WARN = "warn"
    ACTION_RESTRICT = "restrict"
    ACTION_CHOICES = (
        (ACTION_APPROVE, "Approve"),
        (ACTION_REJECT, "Reject"),
        (ACTION_EDIT, "Edit"),
        (ACTION_REMOVE, "Remove"),
        (ACTION_WARN, "Warn"),
        (ACTION_RESTRICT, "Restrict"),
    )

    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="moderation_actions", null=True, blank=True)
    actor_username = models.CharField(max_length=150)  # snapshot of admin username
    actor_role = models.CharField(max_length=16)  # admin/superadmin
    action = models.CharField(max_length=16, choices=ACTION_CHOICES)
    reason = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"ModerationAction({self.action}) by {self.actor_username} on Post#{getattr(self.post, 'id', None)}"


class Feedback(models.Model):
    STATUS_PENDING = "pending"
    STATUS_APPROVED = "approved"
    STATUS_REJECTED = "rejected"
    STATUS_CHOICES = (
        (STATUS_PENDING, "Pending"),
        (STATUS_APPROVED, "Approved"),
        (STATUS_REJECTED, "Rejected"),
    )

    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="feedbacks")
    author = models.ForeignKey(NormalUser, on_delete=models.CASCADE, related_name="feedbacks")
    content = models.TextField()
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [
            models.Index(fields=["status", "created_at"]),
            models.Index(fields=["post", "status"]),
        ]

    def __str__(self):
        return f"Feedback#{self.pk} on Post#{self.post_id} by {self.author_id} ({self.status})"


class UserRestriction(models.Model):
    """Restrictions applied to NormalUser accounts (e.g., posting suspension)."""
    TYPE_POST_SUSPEND = "post_suspend"
    TYPE_ACCOUNT_SUSPEND = "account_suspend"
    TYPE_CHOICES = (
        (TYPE_POST_SUSPEND, "Posting Suspension"),
        (TYPE_ACCOUNT_SUSPEND, "Account Suspension"),
    )

    user = models.ForeignKey(NormalUser, on_delete=models.CASCADE, related_name="restrictions")
    type = models.CharField(max_length=32, choices=TYPE_CHOICES)
    reason = models.TextField(blank=True)
    until = models.DateTimeField(null=True, blank=True)  # null => permanent
    created_by = models.CharField(max_length=150)  # admin username snapshot
    created_at = models.DateTimeField(auto_now_add=True)

    def is_active(self):
        from django.utils import timezone
        if self.until is None:
            return True
        return self.until > timezone.now()

    def __str__(self):
        return f"Restriction({self.type}) for User#{self.user_id} active={self.is_active()}"


class PostReaction(models.Model):
    """Reactions on posts by normal users. Currently supports like.
    Unique per user/post/reaction_type to prevent duplicates.
    """
    REACT_LIKE = "like"
    REACTION_CHOICES = (
        (REACT_LIKE, "Like"),
    )

    user = models.ForeignKey(NormalUser, on_delete=models.CASCADE, related_name="reactions")
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="reactions")
    reaction_type = models.CharField(max_length=16, choices=REACTION_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("user", "post", "reaction_type")
        indexes = [
            models.Index(fields=["post", "reaction_type"]),
            models.Index(fields=["user", "reaction_type"]),
        ]

    def __str__(self):
        return f"Reaction({self.reaction_type}) u#{self.user_id} p#{self.post_id}"


class RewardTransaction(models.Model):
    """Per-action reward record to prevent duplicate awards and enable auditing."""
    ACT_VIEW = "view"
    ACT_LIKE = "like"
    ACT_COMMENT = "comment"
    ACTION_CHOICES = (
        (ACT_VIEW, "View"),
        (ACT_LIKE, "Like"),
        (ACT_COMMENT, "Comment"),
    )

    user = models.ForeignKey(NormalUser, on_delete=models.CASCADE, related_name="reward_transactions")
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="reward_transactions")
    action_type = models.CharField(max_length=16, choices=ACTION_CHOICES)
    tokens = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("user", "post", "action_type")
        indexes = [
            models.Index(fields=["user"]),
            models.Index(fields=["post", "action_type"]),
        ]

    def __str__(self):
        return f"RewardTxn({self.action_type}:{self.tokens}) u#{self.user_id} p#{self.post_id}"


class UserTokenBalance(models.Model):
    """Cumulative token balance per user. Updated when RewardTransaction is created."""
    user = models.OneToOneField(NormalUser, on_delete=models.CASCADE, related_name="token_balance")
    balance = models.PositiveIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"TokenBalance u#{self.user_id} = {self.balance}"
