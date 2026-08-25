"""
Session Views
==============
View and manage active sessions.
"""

import logging

from drf_spectacular.utils import extend_schema
from rest_framework import permissions, serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import UserSession

logger = logging.getLogger(__name__)


class SessionSerializer(serializers.ModelSerializer):
    """Serializer for user session details."""

    class Meta:
        model = UserSession
        fields = [
            "id",
            "ip_address",
            "device_type",
            "device_name",
            "browser",
            "os",
            "country",
            "city",
            "is_active",
            "is_current",
            "created_at",
            "last_activity",
        ]


@extend_schema(tags=["Sessions"])
class ActiveSessionsView(APIView):
    """List all active sessions for the current user."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        sessions = UserSession.objects.filter(
            user=request.user,
            is_active=True,
        )
        serializer = SessionSerializer(sessions, many=True)
        return Response({
            "active_sessions": serializer.data,
            "total": sessions.count(),
        })


@extend_schema(tags=["Sessions"])
class TerminateSessionView(APIView):
    """Terminate a specific session by ID."""

    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, session_id):
        try:
            session = UserSession.objects.get(
                id=session_id,
                user=request.user,
                is_active=True,
            )
        except UserSession.DoesNotExist:
            return Response(
                {"error": "Session not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        session.terminate()

        return Response(
            {"message": "Session terminated successfully."},
            status=status.HTTP_200_OK,
        )


@extend_schema(tags=["Sessions"])
class TerminateAllSessionsView(APIView):
    """Terminate all sessions except the current one."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        sessions = UserSession.objects.filter(
            user=request.user,
            is_active=True,
        )

        count = sessions.count()

        for session in sessions:
            session.terminate()

        return Response(
            {"message": f"Terminated {count} sessions. You will need to log in again."},
            status=status.HTTP_200_OK,
        )
