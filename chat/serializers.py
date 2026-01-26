from rest_framework import serializers
from normal_users.models import NormalUser
from .models import Conversation, Message, MessageAttachment, ReadReceipt


class UserBriefSerializer(serializers.ModelSerializer):
    class Meta:
        model = NormalUser
        fields = ["id", "username", "public_username", "avatar_url"]


class MessageAttachmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = MessageAttachment
        fields = ["id", "media_type", "file_url"]


class MessageSerializer(serializers.ModelSerializer):
    sender = UserBriefSerializer(read_only=True)
    attachments = MessageAttachmentSerializer(many=True, read_only=True)
    receipts = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = [
            "id",
            "conversation",
            "sender",
            "type",
            "content",
            "created_at",
            "attachments",
            "receipts",
        ]

    def get_receipts(self, obj):
        items = obj.receipts.all()
        return [{"user": r.user_id, "status": r.status, "updated_at": r.updated_at} for r in items]


class ConversationSerializer(serializers.ModelSerializer):
    participants = UserBriefSerializer(many=True, read_only=True)
    last_message_at = serializers.DateTimeField(read_only=True)

    class Meta:
        model = Conversation
        fields = ["id", "participants", "last_message_at", "created_at"]


class CreateMessageSerializer(serializers.Serializer):
    type = serializers.ChoiceField(choices=[t for t, _ in Message.TYPE_CHOICES])
    content = serializers.CharField(required=False, allow_blank=True)
    attachments = serializers.ListField(child=serializers.DictField(), required=False)

    def validate(self, attrs):
        t = attrs.get("type")
        content = attrs.get("content", "")
        attachments = attrs.get("attachments", [])
        if t == Message.TYPE_TEXT and not content:
            raise serializers.ValidationError("Text message requires content")
        if t in (Message.TYPE_IMAGE, Message.TYPE_VIDEO, Message.TYPE_AUDIO) and not attachments:
            raise serializers.ValidationError("Media message requires attachments")
        return attrs