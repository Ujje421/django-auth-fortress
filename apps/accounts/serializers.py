"""
User Serializers
=================
Serializers for user CRUD, profile management, and admin operations.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers

User = get_user_model()


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration."""

    password = serializers.CharField(
        write_only=True,
        min_length=10,
        style={"input_type": "password"},
        validators=[validate_password],
    )
    password_confirm = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
    )

    class Meta:
        model = User
        fields = [
            "email",
            "first_name",
            "last_name",
            "password",
            "password_confirm",
        ]

    def validate(self, attrs):
        if attrs["password"] != attrs["password_confirm"]:
            raise serializers.ValidationError(
                {"password_confirm": "Passwords do not match."}
            )
        return attrs

    def create(self, validated_data):
        validated_data.pop("password_confirm")
        return User.objects.create_user(**validated_data)


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profile (read/update)."""

    full_name = serializers.ReadOnlyField()

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "full_name",
            "avatar",
            "phone_number",
            "bio",
            "date_of_birth",
            "role",
            "is_verified",
            "mfa_enabled",
            "created_at",
            "last_active_at",
        ]
        read_only_fields = [
            "id",
            "email",
            "role",
            "is_verified",
            "mfa_enabled",
            "created_at",
            "last_active_at",
        ]


class UserListSerializer(serializers.ModelSerializer):
    """Compact serializer for listing users."""

    full_name = serializers.ReadOnlyField()

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "full_name",
            "role",
            "is_active",
            "is_verified",
            "created_at",
        ]


class UserAdminSerializer(serializers.ModelSerializer):
    """Full serializer for admin user management."""

    full_name = serializers.ReadOnlyField()

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "full_name",
            "phone_number",
            "role",
            "is_active",
            "is_staff",
            "is_verified",
            "mfa_enabled",
            "failed_login_attempts",
            "locked_until",
            "last_login_ip",
            "last_active_at",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "email",
            "mfa_enabled",
            "failed_login_attempts",
            "last_login_ip",
            "last_active_at",
            "created_at",
            "updated_at",
        ]


class ChangePasswordSerializer(serializers.Serializer):
    """Serializer for changing password."""

    old_password = serializers.CharField(
        required=True,
        style={"input_type": "password"},
    )
    new_password = serializers.CharField(
        required=True,
        min_length=10,
        style={"input_type": "password"},
        validators=[validate_password],
    )
    new_password_confirm = serializers.CharField(
        required=True,
        style={"input_type": "password"},
    )

    def validate_old_password(self, value):
        user = self.context["request"].user
        if not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect.")
        return value

    def validate(self, attrs):
        if attrs["new_password"] != attrs["new_password_confirm"]:
            raise serializers.ValidationError(
                {"new_password_confirm": "New passwords do not match."}
            )
        if attrs["old_password"] == attrs["new_password"]:
            raise serializers.ValidationError(
                {"new_password": "New password must be different from the current password."}
            )
        return attrs


class PasswordResetRequestSerializer(serializers.Serializer):
    """Serializer for requesting a password reset email."""

    email = serializers.EmailField(required=True)


class PasswordResetConfirmSerializer(serializers.Serializer):
    """Serializer for confirming a password reset."""

    token = serializers.CharField(required=True)
    uid = serializers.CharField(required=True)
    new_password = serializers.CharField(
        required=True,
        min_length=10,
        validators=[validate_password],
        style={"input_type": "password"},
    )
    new_password_confirm = serializers.CharField(
        required=True,
        style={"input_type": "password"},
    )

    def validate(self, attrs):
        if attrs["new_password"] != attrs["new_password_confirm"]:
            raise serializers.ValidationError(
                {"new_password_confirm": "Passwords do not match."}
            )
        return attrs


class UserActivitySerializer(serializers.Serializer):
    """Serializer for user activity log."""

    id = serializers.UUIDField(read_only=True)
    activity_type = serializers.CharField(read_only=True)
    description = serializers.CharField(read_only=True)
    ip_address = serializers.IPAddressField(read_only=True)
    user_agent = serializers.CharField(read_only=True)
    metadata = serializers.JSONField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)


class RoleUpdateSerializer(serializers.Serializer):
    """Serializer for updating user roles (admin only)."""

    role = serializers.ChoiceField(choices=User.Role.choices)
