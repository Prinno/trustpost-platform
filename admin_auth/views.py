from django.contrib.auth import authenticate, get_user_model
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication

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
