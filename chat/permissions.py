from rest_framework import permissions
from .models import Conversation


class IsParticipant(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if isinstance(obj, Conversation):
            return obj.participants.filter(id=request.user.id).exists()
        # For message, check conversation via view.get_object()
        conv = getattr(obj, "conversation", None)
        if conv is None:
            return False
        return conv.participants.filter(id=request.user.id).exists()