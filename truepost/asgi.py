"""
ASGI config for truepost project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/asgi/
"""

import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from django.urls import path

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "truepost.settings")

django_app = get_asgi_application()

from chat.routing import websocket_urlpatterns  # noqa: E402

application = ProtocolTypeRouter({
	"http": django_app,
	"websocket": AuthMiddlewareStack(
		URLRouter(websocket_urlpatterns)
	),
})
