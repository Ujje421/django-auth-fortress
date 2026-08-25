"""
API Key Serializers
====================
"""

from rest_framework import serializers

from .models import APIKey


class APIKeyCreateSerializer(serializers.Serializer):
    """Create a new API key."""

    name = serializers.CharField(max_length=100)
    scope = serializers.ChoiceField(choices=APIKey.Scope.choices, default="read")
    expires_in_days = serializers.IntegerField(
        required=False,
        min_value=1,
        max_value=365,
        help_text="Number of days until the key expires (optional)",
    )


class APIKeyResponseSerializer(serializers.ModelSerializer):
    """API key details (without the raw key)."""

    is_expired = serializers.ReadOnlyField()

    class Meta:
        model = APIKey
        fields = [
            "id",
            "name",
            "prefix",
            "scope",
            "is_active",
            "is_expired",
            "expires_at",
            "last_used_at",
            "last_used_ip",
            "created_at",
            "revoked_at",
        ]


class APIKeyCreatedSerializer(serializers.Serializer):
    """Response when a new API key is created (includes the raw key)."""

    key = serializers.CharField(help_text="The API key — shown only once!")
    api_key = APIKeyResponseSerializer()
