"""
Authentication Views
======================
JWT login, logout, token refresh, and email verification endpoints.
"""

import logging

from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from drf_spectacular.utils import extend_schema
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from apps.accounts.models import UserActivity
from apps.accounts.utils import log_activity

from .serializers import (
    CustomTokenObtainPairSerializer,
    EmailVerificationSerializer,
    LogoutSerializer,
)
from .throttles import LoginRateThrottle

logger = logging.getLogger(__name__)
User = get_user_model()


@extend_schema(tags=["Auth"])
class LoginView(TokenObtainPairView):
    """
    Login with email and password. Returns JWT access and refresh tokens.
    If MFA is enabled, returns a temporary token requiring TOTP verification.
    """

    serializer_class = CustomTokenObtainPairSerializer
    throttle_classes = [LoginRateThrottle]


@extend_schema(tags=["Auth"])
class TokenRefreshView(TokenRefreshView):
    """Refresh an expired access token using a valid refresh token."""

    pass


@extend_schema(tags=["Auth"])
class LogoutView(APIView):
    """
    Logout by blacklisting the refresh token.
    Prevents reuse of the token after logout.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            token = RefreshToken(serializer.validated_data["refresh"])
            token.blacklist()

            log_activity(
                user=request.user,
                activity_type=UserActivity.ActivityType.LOGOUT,
                description="User logged out",
                request=request,
            )

            return Response(
                {"message": "Successfully logged out."},
                status=status.HTTP_200_OK,
            )
        except TokenError:
            return Response(
                {"error": "Invalid or expired token."},
                status=status.HTTP_400_BAD_REQUEST,
            )


@extend_schema(tags=["Auth"])
class EmailVerifyView(APIView):
    """Verify a user's email address using the emailed token."""

    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            uid = force_str(
                urlsafe_base64_decode(serializer.validated_data["uid"])
            )
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {"error": "Invalid verification link."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        token = serializer.validated_data["token"]
        if not default_token_generator.check_token(user, token):
            return Response(
                {"error": "Verification link has expired."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.verify_email()

        logger.info(f"Email verified: {user.email}")

        return Response(
            {"message": "Email verified successfully."},
            status=status.HTTP_200_OK,
        )


@extend_schema(tags=["Auth"])
class WhoAmIView(APIView):
    """Return the current authenticated user's information."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response(
            {
                "id": str(user.id),
                "email": user.email,
                "full_name": user.full_name,
                "role": user.role,
                "is_verified": user.is_verified,
                "mfa_enabled": user.mfa_enabled,
                "avatar": user.avatar.url if user.avatar else None,
                "created_at": user.created_at.isoformat(),
                "last_active_at": (
                    user.last_active_at.isoformat() if user.last_active_at else None
                ),
            }
        )
