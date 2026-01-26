from channels.generic.websocket import AsyncJsonWebsocketConsumer
from urllib.parse import parse_qs
from normal_users.authentication import decode_jwt
from normal_users.models import NormalUser
from .models import Conversation, Message, ReadReceipt
from asgiref.sync import sync_to_async


class ChatConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        self.user = None
        qs = parse_qs(self.scope.get("query_string", b"").decode())
        token = qs.get("token", [None])[0]
        if not token:
            await self.close(code=4001)
            return
        try:
            data = decode_jwt(token)
            if data.get("sub") != "normal_user_access":
                raise Exception("Invalid subject")
            uid = data.get("uid")
            self.user = await sync_to_async(NormalUser.objects.get)(id=uid)
        except Exception:
            await self.close(code=4002)
            return

        self.conv_id = int(self.scope["url_route"]["kwargs"]["conversation_id"])
        conv = await sync_to_async(Conversation.objects.filter(id=self.conv_id).first)()
        if not conv:
            await self.close(code=4003)
            return
        # Ensure participant
        is_participant = await sync_to_async(conv.participants.filter(id=self.user.id).exists)()
        if not is_participant:
            await self.close(code=4004)
            return

        self.room_group_name = f"chat_{self.conv_id}"
        await self.channel_layer.group_add(self.room_group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        if hasattr(self, "room_group_name"):
            await self.channel_layer.group_discard(self.room_group_name, self.channel_name)

    async def receive_json(self, content, **kwargs):
        event = content.get("event")
        if event == "typing":
            # Broadcast typing indicator
            await self.channel_layer.group_send(
                self.room_group_name,
                {"type": "chat.typing", "user_id": self.user.id, "typing": bool(content.get("typing", True))},
            )
        elif event == "read":
            ids = content.get("message_ids", [])
            await self._mark_read(ids)
            await self.channel_layer.group_send(
                self.room_group_name,
                {"type": "chat.read", "user_id": self.user.id, "message_ids": ids},
            )
        elif event == "message":
            # Messages are generally sent via REST; optionally handle small text here
            pass

    async def chat_typing(self, event):
        await self.send_json({"event": "typing", "user_id": event["user_id"], "typing": event["typing"]})

    async def chat_read(self, event):
        await self.send_json({"event": "read", "user_id": event["user_id"], "message_ids": event["message_ids"]})

    @sync_to_async
    def _mark_read(self, ids):
        for mid in ids:
            try:
                msg = Message.objects.get(id=mid, conversation_id=self.conv_id)
            except Message.DoesNotExist:
                continue
            ReadReceipt.objects.update_or_create(message=msg, user=self.user, defaults={"status": ReadReceipt.STATUS_READ})