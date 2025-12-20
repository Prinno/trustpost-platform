from django.urls import path
from .views import (
    admin_login_view,
    admin_me_view,
    admin_list_view,
    admin_upsert_view,
    admin_delete_view,
    global_settings_view,
)

urlpatterns = [
    path("login/", admin_login_view, name="admin-login"),
    path("me/", admin_me_view, name="admin-me"),
    path("admins/", admin_list_view, name="admin-list"),
    path("admins/upsert/", admin_upsert_view, name="admin-upsert"),
    path("admins/delete/", admin_delete_view, name="admin-delete"),
    path("settings/", global_settings_view, name="global-settings"),
]
