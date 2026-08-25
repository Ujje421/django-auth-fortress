"""
API Key Views
==============
CRUD operations for API key management.
"""

import logging
from datetime import timedelta

from django.utils import timezone
from drf_spectacular.utils import extend_schema
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.models import UserActivity
from apps.accounts.utils import log_activity

from .models import APIKey
from .serializers import (
    APIKeyCreateSerializer,
    APIKeyCreatedSerializer,
    APIKeyResponseSerializer,
)

logger = logging.getLogger(__name__)


@extend_schema(tags=["API Keys"])
class APIKeyListCreateView(APIView):
    """List existing API keys or create a new one."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        """List all API keys for the current user."""
        keys = APIKey.objects.filter(user=request.user)
        serializer = APIKeyResponseSerializer(keys, many=True)
        return Response({"api_keys": serializer.data})

    def post(self, request):
        """
        Create a new API key. The raw key is returned ONLY in this response.
        Store it securely — it cannot be retrieved again.
        """
        serializer = APIKeyCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        expires_at = None
        expires_in_days = serializer.validated_data.get("expires_in_days")
        if expires_in_days:
            expires_at = timezone.now() + timedelta(days=expires_in_days)

        api_key, raw_key = APIKey.create_key(
            user=request.user,
            name=serializer.validated_data["name"],
            scope=serializer.validated_data["scope"],
            expires_at=expires_at,
        )

        log_activity(
            user=request.user,
            activity_type=UserActivity.ActivityType.API_KEY_CREATE,
            description=f"API key created: {api_key.name}",
            request=request,
        )

        return Response(
            {
                "key": raw_key,
                "api_key": APIKeyResponseSerializer(api_key).data,
                "warning": "Save this key now. It will not be shown again!",
            },
            status=status.HTTP_201_CREATED,
        )


@extend_schema(tags=["API Keys"])
class APIKeyDetailView(APIView):
    """View or revoke a specific API key."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, key_id):
        """Get details for a specific API key."""
        try:
            api_key = APIKey.objects.get(id=key_id, user=request.user)
        except APIKey.DoesNotExist:
            return Response(
                {"error": "API key not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        return Response(APIKeyResponseSerializer(api_key).data)

    def delete(self, request, key_id):
        """Revoke (soft-delete) an API key."""
        try:
            api_key = APIKey.objects.get(id=key_id, user=request.user)
        except APIKey.DoesNotExist:
            return Response(
                {"error": "API key not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        api_key.revoke()

        log_activity(
            user=request.user,
            activity_type=UserActivity.ActivityType.API_KEY_REVOKE,
            description=f"API key revoked: {api_key.name}",
            request=request,
        )

        return Response(
            {"message": f"API key '{api_key.name}' has been revoked."},
            status=status.HTTP_200_OK,
        )
