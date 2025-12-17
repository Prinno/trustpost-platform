from django.urls import path
from .views import admin_login_view, admin_me_view

urlpatterns = [
    path("login/", admin_login_view, name="admin-login"),
    path("me/", admin_me_view, name="admin-me"),
]
