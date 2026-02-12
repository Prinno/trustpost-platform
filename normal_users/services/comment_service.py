from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from django.db import transaction
from django.db.models import F
from django.utils import timezone

from ..models import Comment, NormalUser, Post


# Maximum nesting depth for comment replies (0 = top-level)
MAX_COMMENT_DEPTH = 4


@dataclass
class CommentCreateResult:
    comment: Comment
    created: bool


def _sanitize_content(raw: str) -> str:
    """Basic content sanitizer. In production, plug in a real HTML sanitizer.

    Strips leading/trailing whitespace and normalizes extremely long input.
    """

    text = (raw or "").strip()
    # Hard limit to protect DB and rendering; can be tuned.
    if len(text) > 3000:
        text = text[:3000]
    return text


def create_comment(*, user: NormalUser, post: Post, content: str, parent: Optional[Comment] = None) -> CommentCreateResult:
    """Create a new comment or reply.

    - Enforces maximum depth.
    - Prevents replying to deleted comments.
    - Prevents cross-post replies.
    - Uses atomic counters for post.comment_count and parent.reply_count.
    """

    if not user or not isinstance(user, NormalUser):
        raise ValueError("Valid normal user is required")

    if not post or not isinstance(post, Post):
        raise ValueError("Valid post is required")

    text = _sanitize_content(content)
    if not text:
        raise ValueError("Content is required")

    parent_obj: Optional[Comment] = parent
    depth = 0
    if parent_obj is not None:
        # Reload with row-level lock if needed
        parent_obj = Comment.objects.select_for_update().filter(pk=parent_obj.pk).first() or parent_obj
        if parent_obj.is_deleted:
            raise ValueError("Cannot reply to a deleted comment")
        if parent_obj.post_id != post.id:
            raise ValueError("Parent comment belongs to a different post")
        depth = (parent_obj.depth or 0) + 1
        if depth > MAX_COMMENT_DEPTH:
            raise ValueError("Maximum reply depth exceeded")

    with transaction.atomic():
        comment = Comment.objects.create(
            post=post,
            user=user,
            parent=parent_obj,
            depth=depth,
            content=text,
            is_deleted=False,
            created_at=timezone.now(),
        )
        # Update denormalized counters atomically.
        # comment_count tracks only top-level threads; replies affect only reply_count.
        if parent_obj is None:
            Post.objects.filter(pk=post.pk).update(comment_count=F("comment_count") + 1)
        else:
            Comment.objects.filter(pk=parent_obj.pk).update(reply_count=F("reply_count") + 1)

    return CommentCreateResult(comment=comment, created=True)


def edit_comment(*, user: NormalUser, comment: Comment, content: str) -> Comment:
    """Edit an existing comment.

    - Only the owner can edit.
    - Cannot edit deleted comments.
    """

    if comment.user_id != user.id:
        raise PermissionError("You can only edit your own comments")
    if comment.is_deleted:
        raise ValueError("Cannot edit a deleted comment")

    text = _sanitize_content(content)
    if not text:
        raise ValueError("Content is required")

    comment.content = text
    comment.save(update_fields=["content", "updated_at"])
    return comment


def soft_delete_comment(*, user: NormalUser, comment: Comment) -> Comment:
    """Soft-delete a comment.

    - Marks is_deleted=True instead of removing the row.
    - Decrements post.comment_count for top-level comments only.
    - Decrements parent.reply_count if applicable.
    - Leaves replies in place; UI can decide how to render them.
    """

    if comment.user_id != user.id:
        raise PermissionError("You can only delete your own comments")
    if comment.is_deleted:
        return comment

    with transaction.atomic():
        comment.is_deleted = True
        comment.save(update_fields=["is_deleted", "updated_at"])
        if comment.parent_id is None:
            Post.objects.filter(pk=comment.post_id).update(comment_count=F("comment_count") - 1)
        if comment.parent_id:
            Comment.objects.filter(pk=comment.parent_id).update(reply_count=F("reply_count") - 1)

    return comment


def get_top_level_comments_queryset(post: Post):
    """Base queryset for paginated top-level comments on a post.

    Uses select_related to avoid N+1 on user.
    """

    return (
        Comment.objects.filter(post=post, parent__isnull=True)
        .select_related("user")
        .order_by("created_at", "id")
    )


def get_replies_queryset(parent: Comment):
    """Base queryset for paginated direct replies to a comment."""

    return (
        Comment.objects.filter(parent=parent)
        .select_related("user")
        .order_by("created_at", "id")
    )
