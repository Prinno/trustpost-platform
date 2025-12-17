from django.contrib.auth.hashers import check_password, make_password
from django.utils import timezone
from rest_framework import serializers

from .models import NormalUser, VerificationToken, PhoneOTP, RefreshToken


class NormalUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = NormalUser
        fields = [
            "id",
            "email",
            "phone",
            "is_active",
            "is_email_verified",
            "is_phone_verified",
            "created_at",
        ]


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False, allow_null=True, allow_blank=True)
    phone = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    password = serializers.CharField(write_only=True, min_length=8)

    def validate(self, attrs):
        email = attrs.get("email")
        phone = attrs.get("phone")
        if not email and not phone:
            raise serializers.ValidationError("Provide either email or phone.")
        if email and NormalUser.objects.filter(email=email).exists():
            raise serializers.ValidationError("Email already registered.")
        if phone and NormalUser.objects.filter(phone=phone).exists():
            raise serializers.ValidationError("Phone already registered.")
        return attrs

    def create(self, validated_data):
        pwd = validated_data.pop("password")
        user = NormalUser.objects.create(
            password=make_password(pwd),
            is_active=False,
            is_email_verified=False,
            is_phone_verified=False,
            **validated_data,
        )
        return user


class LoginSerializer(serializers.Serializer):
    identifier = serializers.CharField()
    password = serializers.CharField(write_only=True)

    # Do not perform user lookup here; handled in view for unified flow
    def validate(self, attrs):
        if not attrs.get("identifier") or not attrs.get("password"):
            raise serializers.ValidationError("identifier and password are required")
        return attrs


class RequestEmailVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, attrs):
        email = attrs["email"]
        try:
            user = NormalUser.objects.get(email=email)
        except NormalUser.DoesNotExist:
            raise serializers.ValidationError("No account with this email.")
        attrs["user"] = user
        return attrs


class VerifyEmailSerializer(serializers.Serializer):
    token = serializers.CharField()


class RequestPhoneOTPSerializer(serializers.Serializer):
    phone = serializers.CharField()

    def validate(self, attrs):
        phone = attrs["phone"]
        try:
            user = NormalUser.objects.get(phone=phone)
        except NormalUser.DoesNotExist:
            raise serializers.ValidationError("No account with this phone.")
        attrs["user"] = user
        return attrs


class VerifyPhoneOTPSerializer(serializers.Serializer):
    phone = serializers.CharField()
    code = serializers.CharField(max_length=6)


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False, allow_null=True)
    phone = serializers.CharField(required=False, allow_null=True)

    def validate(self, attrs):
        email = attrs.get("email")
        phone = attrs.get("phone")
        if not email and not phone:
            raise serializers.ValidationError("Provide email or phone.")
        user = None
        if email:
            user = NormalUser.objects.filter(email=email).first()
        if not user and phone:
            user = NormalUser.objects.filter(phone=phone).first()
        if not user:
            raise serializers.ValidationError("Account not found.")
        attrs["user"] = user
        return attrs


class PasswordResetConfirmSerializer(serializers.Serializer):
    # Either email token or phone+code
    token = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    phone = serializers.CharField(required=False, allow_null=True)
    code = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    new_password = serializers.CharField(min_length=8)
