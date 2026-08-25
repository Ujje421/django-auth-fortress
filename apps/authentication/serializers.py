"""
Authentication Serializers
============================
Custom JWT token serializers with extended claims and MFA support.
"""

from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

User = get_user_model()


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom JWT token serializer that includes additional user claims
    and checks for MFA requirement.
    """

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token["email"] = user.email
        token["role"] = user.role
        token["full_name"] = user.full_name
        token["is_verified"] = user.is_verified
        token["mfa_enabled"] = user.mfa_enabled

        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        user = self.user

        # Check if account is locked
        if user.is_locked:
            raise serializers.ValidationError(
                "Account is temporarily locked. Please try again later."
            )

        # If MFA is enabled, require TOTP verification
        if user.mfa_enabled:
            data["mfa_required"] = True
            data["mfa_token"] = str(data.pop("access", ""))
            data.pop("refresh", None)
            data["message"] = "MFA verification required. Use /api/v1/mfa/verify/ with your TOTP code."
            return data

        # Add user info to response
        data["user"] = {
            "id": str(user.id),
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "is_verified": user.is_verified,
            "mfa_enabled": user.mfa_enabled,
        }

        return data


class TokenRefreshResponseSerializer(serializers.Serializer):
    """Serializer for token refresh response."""

    access = serializers.CharField()
    refresh = serializers.CharField()


class LogoutSerializer(serializers.Serializer):
    """Serializer for logout (token blacklisting)."""

    refresh = serializers.CharField(required=True)


class EmailVerificationSerializer(serializers.Serializer):
    """Serializer for email verification."""

    uid = serializers.CharField(required=True)
    token = serializers.CharField(required=True)
