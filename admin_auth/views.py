from django.contrib.auth import authenticate, get_user_model
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from .models import AdminAccount, GlobalSetting
from .permissions import IsSuperAdmin

User = get_user_model()


@api_view(["POST"])
@permission_classes([AllowAny])
def admin_login_view(request):
    identifier = request.data.get("identifier", "").strip()
    password = request.data.get("password")
    if not identifier or not password:
        return Response({"detail": "identifier and password are required"}, status=400)

    # Support username or email
    username = identifier
    if "@" in identifier:
        try:
            user = User.objects.get(email=identifier)
            username = user.get_username()
        except User.DoesNotExist:
            return Response({"detail": "Invalid credentials"}, status=401)

    user = authenticate(username=username, password=password)
    if not user:
        return Response({"detail": "Invalid credentials"}, status=401)

    # Only staff or superusers allowed
    if not (user.is_staff or user.is_superuser):
        return Response({"detail": "Not permitted"}, status=403)

    token, _ = Token.objects.get_or_create(user=user)
    role = "superadmin" if user.is_superuser else "admin"
    return Response({"token": token.key, "role": role})


@api_view(["GET"])
@authentication_classes([TokenAuthentication])
def admin_me_view(request):
    user = request.user
    role = "superadmin" if user.is_superuser else ("admin" if user.is_staff else "user")
    return Response({
        "username": user.get_username(),
        "email": getattr(user, "email", None),
        "role": role,
    })


# Super Admin management endpoints
@api_view(["GET"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsSuperAdmin])
def admin_list_view(request):
    data = []
    for acc in AdminAccount.objects.select_related("user").all():
        data.append({
            "id": acc.id,
            "username": acc.user.get_username(),
            "email": getattr(acc.user, "email", None),
            "role": acc.role,
            "is_enabled": acc.is_enabled,
            "permissions": acc.permissions,
        })
    return Response(data)


@api_view(["POST"])  # create or update admin accounts
@authentication_classes([TokenAuthentication])
@permission_classes([IsSuperAdmin])
def admin_upsert_view(request):
    username = (request.data.get("username") or "").strip()
    email = (request.data.get("email") or "").strip()
    password = request.data.get("password")
    role = (request.data.get("role") or AdminAccount.ROLE_ADMIN).strip()
    is_enabled = bool(request.data.get("is_enabled", True))
    permissions = request.data.get("permissions") or {}

    if role not in {AdminAccount.ROLE_ADMIN, AdminAccount.ROLE_SUPERADMIN}:
        return Response({"detail": "Invalid role"}, status=400)
    if not username or not password:
        return Response({"detail": "username and password are required"}, status=400)

    user = User.objects.filter(username=username).first()
    if user:
        # Update existing
        user.email = email or user.email
        user.is_staff = True
        if role == AdminAccount.ROLE_SUPERADMIN:
            user.is_superuser = True
        user.set_password(password)
        user.save()
        acc, _ = AdminAccount.objects.get_or_create(user=user)
        acc.role = role
        acc.is_enabled = is_enabled
        acc.permissions = permissions
        acc.save()
        return Response({"detail": "Admin updated"})
    else:
        # Create new
        user = User.objects.create_user(username=username, email=email or None, password=password)
        user.is_staff = True
        user.is_superuser = (role == AdminAccount.ROLE_SUPERADMIN)
        user.save()
        acc = AdminAccount.objects.create(user=user, role=role, is_enabled=is_enabled, permissions=permissions)
        return Response({"detail": "Admin created", "id": acc.id})


@api_view(["POST"])  # delete admin account
@authentication_classes([TokenAuthentication])
@permission_classes([IsSuperAdmin])
def admin_delete_view(request):
    username = (request.data.get("username") or "").strip()
    if not username:
        return Response({"detail": "username is required"}, status=400)
    user = User.objects.filter(username=username).first()
    if not user:
        return Response({"detail": "User not found"}, status=404)
    AdminAccount.objects.filter(user=user).delete()
    user.delete()
    return Response({"detail": "Admin deleted"})


@api_view(["GET", "POST"])  # manage global settings
@authentication_classes([TokenAuthentication])
@permission_classes([IsSuperAdmin])
def global_settings_view(request):
    if request.method == "GET":
        data = {gs.key: gs.value for gs in GlobalSetting.objects.all()}
        return Response(data)
    # POST to set/update
    key = (request.data.get("key") or "").strip()
    value = request.data.get("value") or {}
    if not key:
        return Response({"detail": "key is required"}, status=400)
    gs, _ = GlobalSetting.objects.get_or_create(key=key)
    gs.value = value
    gs.save()
    return Response({"detail": "Setting saved"})
