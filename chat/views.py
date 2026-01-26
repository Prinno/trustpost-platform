from django.db.models import Q
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from normal_users.authentication import AuthenticatedNormalUser
from normal_users.models import NormalUser
from .models import Conversation, Message, MessageAttachment, ReadReceipt
from .serializers import (
    ConversationSerializer,
    MessageSerializer,
    CreateMessageSerializer,
)
from .permissions import IsParticipant


class ConversationViewSet(viewsets.ModelViewSet):
    queryset = Conversation.objects.all()
    serializer_class = ConversationSerializer
    permission_classes = [IsAuthenticated, IsParticipant]

    def get_queryset(self):
        user = self.request.user
        if isinstance(user, AuthenticatedNormalUser):
            user = user.normal_user
        return Conversation.objects.filter(participants=user).order_by("-last_message_at", "-id")

    def perform_create(self, serializer):
        serializer.save()

    @action(detail=False, methods=["post"], url_path="create_or_get")
    def create_or_get(self, request):
        target_id = request.data.get("target_user_id")
        if not target_id:
            return Response({"detail": "target_user_id required"}, status=400)
        try:
            target = NormalUser.objects.get(id=target_id)
        except NormalUser.DoesNotExist:
            return Response({"detail": "Target user not found"}, status=404)
        user = request.user
        if isinstance(user, AuthenticatedNormalUser):
            user = user.normal_user
        # find conversation with exactly these two participants
        conv = Conversation.objects.filter(participants=user).filter(participants=target).first()
        if not conv:
            conv = Conversation.objects.create()
            conv.participants.add(user, target)
        return Response(ConversationSerializer(conv).data)

    @action(detail=True, methods=["get"], url_path="messages")
    def messages(self, request, pk=None):
        conv = self.get_object()
        # pagination
        limit = int(request.query_params.get("limit", 30))
        before_id = request.query_params.get("before_id")
        qs = Message.objects.filter(conversation=conv).order_by("-id")
        if before_id:
            qs = qs.filter(id__lt=before_id)
        items = list(qs[:limit][::-1])  # return ascending order
        return Response(MessageSerializer(items, many=True).data)

    @action(detail=True, methods=["post"], url_path="send")
    def send(self, request, pk=None):
        conv = self.get_object()
        ser = CreateMessageSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        data = ser.validated_data
        user = request.user
        if isinstance(user, AuthenticatedNormalUser):
            user = user.normal_user
        msg = Message.objects.create(
            conversation=conv,
            sender=user,
            type=data["type"],
            content=data.get("content", ""),
        )
        for att in data.get("attachments", []):
            MessageAttachment.objects.create(
                message=msg,
                media_type=att.get("media_type", "image"),
                file_url=att.get("file_url", ""),
            )
        conv.last_message_at = msg.created_at
        conv.save(update_fields=["last_message_at"])
        # initialize receipts (delivered to both participants except sender)
        for u in conv.participants.all():
            if u.id == user.id:
                ReadReceipt.objects.update_or_create(message=msg, user=u, defaults={"status": ReadReceipt.STATUS_SENT})
            else:
                ReadReceipt.objects.update_or_create(message=msg, user=u, defaults={"status": ReadReceipt.STATUS_DELIVERED})
        return Response(MessageSerializer(msg).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"], url_path="mark_read")
    def mark_read(self, request, pk=None):
        conv = self.get_object()
        ids = request.data.get("message_ids", [])
        user = request.user
        if isinstance(user, AuthenticatedNormalUser):
            user = user.normal_user
        for mid in ids:
            try:
                msg = Message.objects.get(id=mid, conversation=conv)
            except Message.DoesNotExist:
                continue
            ReadReceipt.objects.update_or_create(
                message=msg, user=user, defaults={"status": ReadReceipt.STATUS_READ}
            )
        return Response({"ok": True})