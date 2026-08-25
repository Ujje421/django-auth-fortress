"""
Account Views
==============
User profile, admin management, password operations, and activity log endpoints.
"""

import logging

from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils import timezone
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import UserActivity
from .permissions import IsAdmin, IsOwnerOrAdmin
from .serializers import (
    ChangePasswordSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    RoleUpdateSerializer,
    UserActivitySerializer,
    UserAdminSerializer,
    UserListSerializer,
    UserProfileSerializer,
    UserRegistrationSerializer,
)
from .utils import log_activity, send_password_reset_email

logger = logging.getLogger(__name__)
User = get_user_model()


# ─── Registration ────────────────────────────────────────────


@extend_schema(tags=["Auth"])
class RegisterView(generics.CreateAPIView):
    """Register a new user account."""

    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        log_activity(
            user=user,
            activity_type=UserActivity.ActivityType.LOGIN,
            description="Account created",
            request=request,
        )

        logger.info(f"New user registered: {user.email}")

        return Response(
            {
                "message": "Registration successful. Please verify your email.",
                "user": UserProfileSerializer(user).data,
            },
            status=status.HTTP_201_CREATED,
        )


# ─── Profile ─────────────────────────────────────────────────


@extend_schema_view(
    get=extend_schema(tags=["Users"], summary="Get current user profile"),
    put=extend_schema(tags=["Users"], summary="Update current user profile"),
    patch=extend_schema(tags=["Users"], summary="Partial update current user profile"),
)
class ProfileView(generics.RetrieveUpdateAPIView):
    """Get or update the current user's profile."""

    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

    def perform_update(self, serializer):
        serializer.save()
        log_activity(
            user=self.request.user,
            activity_type=UserActivity.ActivityType.PROFILE_UPDATE,
            description="Profile updated",
            request=self.request,
        )


# ─── Password Change ─────────────────────────────────────────


@extend_schema(tags=["Users"])
class ChangePasswordView(APIView):
    """Change the current user's password."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)

        user = request.user
        user.set_password(serializer.validated_data["new_password"])
        user.password_changed_at = timezone.now()
        user.save(update_fields=["password", "password_changed_at", "updated_at"])

        log_activity(
            user=user,
            activity_type=UserActivity.ActivityType.PASSWORD_CHANGE,
            description="Password changed",
            request=request,
        )

        return Response(
            {"message": "Password changed successfully."},
            status=status.HTTP_200_OK,
        )


# ─── Password Reset ──────────────────────────────────────────


@extend_schema(tags=["Auth"])
class PasswordResetRequestView(APIView):
    """Request a password reset email."""

    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]

        try:
            user = User.objects.get(email=email, is_active=True)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            send_password_reset_email(user, uid, token)
        except User.DoesNotExist:
            pass  # Don't reveal whether the email exists

        return Response(
            {"message": "If that email is registered, a reset link has been sent."},
            status=status.HTTP_200_OK,
        )


@extend_schema(tags=["Auth"])
class PasswordResetConfirmView(APIView):
    """Confirm a password reset with token."""

    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            uid = force_str(
                urlsafe_base64_decode(serializer.validated_data["uid"])
            )
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {"error": "Invalid reset link."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        token = serializer.validated_data["token"]
        if not default_token_generator.check_token(user, token):
            return Response(
                {"error": "Reset link has expired or is invalid."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(serializer.validated_data["new_password"])
        user.password_changed_at = timezone.now()
        user.save(update_fields=["password", "password_changed_at", "updated_at"])

        log_activity(
            user=user,
            activity_type=UserActivity.ActivityType.PASSWORD_RESET,
            description="Password reset via email",
            request=request,
        )

        return Response(
            {"message": "Password has been reset successfully."},
            status=status.HTTP_200_OK,
        )


# ─── Activity Log ────────────────────────────────────────────


@extend_schema(tags=["Users"])
class ActivityLogView(generics.ListAPIView):
    """List the current user's activity log."""

    serializer_class = UserActivitySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return UserActivity.objects.filter(user=self.request.user)[:50]


# ─── Admin: User Management ──────────────────────────────────


@extend_schema_view(
    get=extend_schema(tags=["Users"], summary="List all users (Admin)"),
)
class AdminUserListView(generics.ListAPIView):
    """Admin endpoint to list all users with filters."""

    serializer_class = UserListSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdmin]
    queryset = User.objects.all()
    filterset_fields = ["role", "is_active", "is_verified"]
    search_fields = ["email", "first_name", "last_name"]
    ordering_fields = ["created_at", "email", "role"]


@extend_schema_view(
    get=extend_schema(tags=["Users"], summary="Get user detail (Admin)"),
    put=extend_schema(tags=["Users"], summary="Update user (Admin)"),
    patch=extend_schema(tags=["Users"], summary="Partial update user (Admin)"),
    delete=extend_schema(tags=["Users"], summary="Delete user (Admin)"),
)
class AdminUserDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Admin endpoint to manage individual users."""

    serializer_class = UserAdminSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdmin]
    queryset = User.objects.all()
    lookup_field = "id"


@extend_schema(tags=["Users"])
class AdminRoleUpdateView(APIView):
    """Admin endpoint to update a user's role."""

    permission_classes = [permissions.IsAuthenticated, IsAdmin]

    def patch(self, request, user_id):
        serializer = RoleUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        old_role = user.role
        user.role = serializer.validated_data["role"]
        user.save(update_fields=["role", "updated_at"])

        logger.info(
            f"Role updated: {user.email} from {old_role} to {user.role} "
            f"by {request.user.email}"
        )

        return Response(
            {
                "message": f"Role updated from {old_role} to {user.role}.",
                "user": UserAdminSerializer(user).data,
            },
            status=status.HTTP_200_OK,
        )


@extend_schema(tags=["Users"])
class AdminUnlockAccountView(APIView):
    """Admin endpoint to unlock a locked user account."""

    permission_classes = [permissions.IsAuthenticated, IsAdmin]

    def post(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        user.failed_login_attempts = 0
        user.locked_until = None
        user.save(update_fields=["failed_login_attempts", "locked_until", "updated_at"])

        log_activity(
            user=user,
            activity_type=UserActivity.ActivityType.ACCOUNT_UNLOCK,
            description=f"Account unlocked by admin {request.user.email}",
            request=request,
        )

        return Response(
            {"message": f"Account {user.email} has been unlocked."},
            status=status.HTTP_200_OK,
        )
