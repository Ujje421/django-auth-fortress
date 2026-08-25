"""
OAuth Views
============
Social authentication endpoints for Google and GitHub.
"""

import logging

import requests
from django.conf import settings
from django.contrib.auth import get_user_model
from drf_spectacular.utils import extend_schema
from rest_framework import permissions, serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import UserActivity
from apps.accounts.utils import log_activity

logger = logging.getLogger(__name__)
User = get_user_model()


class SocialLoginSerializer(serializers.Serializer):
    """Serializer for social login with authorization code."""

    code = serializers.CharField(required=True, help_text="Authorization code from OAuth provider")
    redirect_uri = serializers.URLField(required=False, help_text="OAuth redirect URI")


def get_tokens_for_user(user):
    """Generate JWT tokens for a user."""
    refresh = RefreshToken.for_user(user)

    # Add custom claims
    refresh["email"] = user.email
    refresh["role"] = user.role
    refresh["full_name"] = user.full_name

    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }


@extend_schema(tags=["OAuth"])
class GoogleLoginView(APIView):
    """
    Authenticate with Google OAuth2.
    Exchange the authorization code for user info and JWT tokens.
    """

    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = SocialLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        code = serializer.validated_data["code"]
        redirect_uri = serializer.validated_data.get(
            "redirect_uri", f"{settings.FRONTEND_URL}/oauth/google/callback"
        )

        # Exchange code for tokens
        try:
            token_response = requests.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "client_id": settings.SOCIALACCOUNT_PROVIDERS["google"]["APP"]["client_id"],
                    "client_secret": settings.SOCIALACCOUNT_PROVIDERS["google"]["APP"]["secret"],
                    "redirect_uri": redirect_uri,
                    "grant_type": "authorization_code",
                },
                timeout=10,
            )
            token_data = token_response.json()

            if "error" in token_data:
                return Response(
                    {"error": f"Google OAuth error: {token_data.get('error_description', 'Unknown error')}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Get user info
            user_response = requests.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {token_data['access_token']}"},
                timeout=10,
            )
            user_data = user_response.json()

        except requests.RequestException as e:
            logger.error(f"Google OAuth request failed: {e}")
            return Response(
                {"error": "Failed to communicate with Google."},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        # Get or create user
        email = user_data.get("email")
        if not email:
            return Response(
                {"error": "Email not provided by Google."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                "first_name": user_data.get("given_name", ""),
                "last_name": user_data.get("family_name", ""),
                "is_verified": True,
            },
        )

        if created:
            user.set_unusable_password()
            user.save()
            logger.info(f"New user created via Google OAuth: {email}")

        tokens = get_tokens_for_user(user)

        log_activity(
            user=user,
            activity_type=UserActivity.ActivityType.LOGIN,
            description="Login via Google OAuth",
            request=request,
            metadata={"provider": "google", "new_account": created},
        )

        return Response(
            {
                "tokens": tokens,
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "full_name": user.full_name,
                    "role": user.role,
                    "is_verified": user.is_verified,
                },
                "created": created,
            },
            status=status.HTTP_200_OK,
        )


@extend_schema(tags=["OAuth"])
class GitHubLoginView(APIView):
    """
    Authenticate with GitHub OAuth2.
    Exchange the authorization code for user info and JWT tokens.
    """

    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = SocialLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        code = serializer.validated_data["code"]

        try:
            # Exchange code for access token
            token_response = requests.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": settings.SOCIALACCOUNT_PROVIDERS["github"]["APP"]["client_id"],
                    "client_secret": settings.SOCIALACCOUNT_PROVIDERS["github"]["APP"]["secret"],
                    "code": code,
                },
                headers={"Accept": "application/json"},
                timeout=10,
            )
            token_data = token_response.json()

            if "error" in token_data:
                return Response(
                    {"error": f"GitHub OAuth error: {token_data.get('error_description', 'Unknown error')}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            access_token = token_data["access_token"]

            # Get user info
            user_response = requests.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10,
            )
            user_data = user_response.json()

            # Get email (may need separate call)
            email = user_data.get("email")
            if not email:
                email_response = requests.get(
                    "https://api.github.com/user/emails",
                    headers={"Authorization": f"Bearer {access_token}"},
                    timeout=10,
                )
                emails = email_response.json()
                primary_email = next(
                    (e for e in emails if e.get("primary")), None
                )
                email = primary_email["email"] if primary_email else None

        except requests.RequestException as e:
            logger.error(f"GitHub OAuth request failed: {e}")
            return Response(
                {"error": "Failed to communicate with GitHub."},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        if not email:
            return Response(
                {"error": "Could not retrieve email from GitHub."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Parse name
        full_name = user_data.get("name", "")
        name_parts = full_name.split(" ", 1) if full_name else ["", ""]

        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                "first_name": name_parts[0],
                "last_name": name_parts[1] if len(name_parts) > 1 else "",
                "is_verified": True,
            },
        )

        if created:
            user.set_unusable_password()
            user.save()
            logger.info(f"New user created via GitHub OAuth: {email}")

        tokens = get_tokens_for_user(user)

        log_activity(
            user=user,
            activity_type=UserActivity.ActivityType.LOGIN,
            description="Login via GitHub OAuth",
            request=request,
            metadata={"provider": "github", "new_account": created},
        )

        return Response(
            {
                "tokens": tokens,
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "full_name": user.full_name,
                    "role": user.role,
                    "is_verified": user.is_verified,
                },
                "created": created,
            },
            status=status.HTTP_200_OK,
        )


@extend_schema(tags=["OAuth"])
class OAuthProvidersView(APIView):
    """List available OAuth providers and their authorization URLs."""

    permission_classes = [permissions.AllowAny]

    def get(self, request):
        providers = []

        google_client_id = settings.SOCIALACCOUNT_PROVIDERS.get("google", {}).get("APP", {}).get("client_id")
        if google_client_id:
            providers.append({
                "name": "google",
                "authorization_url": (
                    f"https://accounts.google.com/o/oauth2/v2/auth"
                    f"?client_id={google_client_id}"
                    f"&redirect_uri={settings.FRONTEND_URL}/oauth/google/callback"
                    f"&response_type=code"
                    f"&scope=openid+email+profile"
                    f"&access_type=online"
                ),
            })

        github_client_id = settings.SOCIALACCOUNT_PROVIDERS.get("github", {}).get("APP", {}).get("client_id")
        if github_client_id:
            providers.append({
                "name": "github",
                "authorization_url": (
                    f"https://github.com/login/oauth/authorize"
                    f"?client_id={github_client_id}"
                    f"&scope=user:email"
                ),
            })

        return Response({"providers": providers})
