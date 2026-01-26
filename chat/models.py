from django.db import models
from django.utils import timezone
from normal_users.models import NormalUser


class Conversation(models.Model):
    participants = models.ManyToManyField(NormalUser, related_name="conversations")
    created_at = models.DateTimeField(auto_now_add=True)
    last_message_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["last_message_at"]),
        ]

    def __str__(self):
        return f"Conversation#{self.pk}"


class Message(models.Model):
    TYPE_TEXT = "text"
    TYPE_IMAGE = "image"
    TYPE_VIDEO = "video"
    TYPE_AUDIO = "audio"
    TYPE_CHOICES = (
        (TYPE_TEXT, "Text"),
        (TYPE_IMAGE, "Image"),
        (TYPE_VIDEO, "Video"),
        (TYPE_AUDIO, "Audio"),
    )

    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name="messages")
    sender = models.ForeignKey(NormalUser, on_delete=models.CASCADE, related_name="sent_messages")
    type = models.CharField(max_length=16, choices=TYPE_CHOICES, default=TYPE_TEXT)
    content = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_deleted_globally = models.BooleanField(default=False)
    deleted_by = models.ManyToManyField(NormalUser, related_name="deleted_messages", blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [
            models.Index(fields=["conversation", "created_at"]),
            models.Index(fields=["sender", "created_at"]),
        ]

    def __str__(self):
        return f"Message#{self.pk} in Conv#{self.conversation_id}"


class MessageAttachment(models.Model):
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name="attachments")
    media_type = models.CharField(max_length=16)
    file_url = models.URLField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Attachment#{self.pk} for Msg#{self.message_id}"


class ReadReceipt(models.Model):
    STATUS_SENT = "sent"
    STATUS_DELIVERED = "delivered"
    STATUS_READ = "read"
    STATUS_CHOICES = (
        (STATUS_SENT, "Sent"),
        (STATUS_DELIVERED, "Delivered"),
        (STATUS_READ, "Read"),
    )

    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name="receipts")
    user = models.ForeignKey(NormalUser, on_delete=models.CASCADE, related_name="message_receipts")
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_DELIVERED)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("message", "user")
        indexes = [
            models.Index(fields=["message", "user", "status"]),
        ]

    def mark_read(self):
        self.status = self.STATUS_READ
        self.updated_at = timezone.now()
        self.save(update_fields=["status", "updated_at"])