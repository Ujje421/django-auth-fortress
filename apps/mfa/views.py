"""
MFA Views
==========
Setup, confirm, verify, and disable TOTP-based two-factor authentication.
"""

import base64
import io
import logging

import qrcode
from django.utils import timezone
from drf_spectacular.utils import extend_schema
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from apps.accounts.models import UserActivity
from apps.accounts.utils import log_activity

from .models import TOTPDevice
from .serializers import (
    MFAConfirmSerializer,
    MFADisableSerializer,
    MFAVerifySerializer,
)

logger = logging.getLogger(__name__)


@extend_schema(tags=["MFA"])
class MFASetupView(APIView):
    """
    Initialize MFA setup. Returns a TOTP secret, QR code, and backup codes.
    The user must scan the QR code and confirm with a valid TOTP code.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user

        if user.mfa_enabled:
            return Response(
                {"error": "MFA is already enabled. Disable it first to reconfigure."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Create or reset TOTP device
        device = TOTPDevice.create_for_user(user)

        # Generate QR code
        provisioning_uri = device.get_provisioning_uri()
        qr = qrcode.make(provisioning_uri)
        buffer = io.BytesIO()
        qr.save(buffer, format="PNG")
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()

        return Response(
            {
                "secret": device.secret,
                "provisioning_uri": provisioning_uri,
                "qr_code": f"data:image/png;base64,{qr_base64}",
                "backup_codes": device.backup_codes,
                "message": "Scan the QR code with your authenticator app, then confirm with a code.",
            },
            status=status.HTTP_200_OK,
        )


@extend_schema(tags=["MFA"])
class MFAConfirmView(APIView):
    """
    Confirm MFA setup by verifying a TOTP code from the authenticator app.
    This activates MFA on the user's account.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = MFAConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user

        try:
            device = TOTPDevice.objects.get(user=user)
        except TOTPDevice.DoesNotExist:
            return Response(
                {"error": "MFA setup not initialized. Call /api/v1/mfa/setup/ first."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        code = serializer.validated_data["code"]
        if not device.verify_code(code):
            return Response(
                {"error": "Invalid TOTP code. Please try again."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Activate MFA
        device.is_confirmed = True
        device.last_used_at = timezone.now()
        device.save(update_fields=["is_confirmed", "last_used_at"])

        user.mfa_enabled = True
        user.save(update_fields=["mfa_enabled", "updated_at"])

        log_activity(
            user=user,
            activity_type=UserActivity.ActivityType.MFA_ENABLE,
            description="Two-factor authentication enabled",
            request=request,
        )

        return Response(
            {"message": "MFA has been successfully enabled."},
            status=status.HTTP_200_OK,
        )


@extend_schema(tags=["MFA"])
class MFAVerifyView(APIView):
    """
    Verify MFA during login. Exchange the temporary MFA token + TOTP code
    for full JWT access and refresh tokens.
    """

    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = MFAVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        mfa_token = serializer.validated_data["mfa_token"]
        code = serializer.validated_data["code"]

        # Decode the temporary token to get the user
        try:
            token = AccessToken(mfa_token)
            user_id = token["user_id"]
        except Exception:
            return Response(
                {"error": "Invalid or expired MFA token."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        from django.contrib.auth import get_user_model

        User = get_user_model()
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            device = TOTPDevice.objects.get(user=user, is_confirmed=True)
        except TOTPDevice.DoesNotExist:
            return Response(
                {"error": "MFA not configured."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Try TOTP code first, then backup code
        verified = device.verify_code(code)
        used_backup = False

        if not verified:
            verified = device.verify_backup_code(code)
            used_backup = True

        if not verified:
            return Response(
                {"error": "Invalid verification code."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Update device
        device.last_used_at = timezone.now()
        device.save(update_fields=["last_used_at"])

        # Generate full tokens
        refresh = RefreshToken.for_user(user)
        refresh["email"] = user.email
        refresh["role"] = user.role
        refresh["full_name"] = user.full_name

        log_activity(
            user=user,
            activity_type=UserActivity.ActivityType.LOGIN,
            description=f"MFA verified (backup_code={used_backup})",
            request=request,
        )

        response_data = {
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": {
                "id": str(user.id),
                "email": user.email,
                "full_name": user.full_name,
                "role": user.role,
            },
        }

        if used_backup:
            remaining = len(device.backup_codes)
            response_data["warning"] = (
                f"You used a backup code. {remaining} backup codes remaining."
            )

        return Response(response_data, status=status.HTTP_200_OK)


@extend_schema(tags=["MFA"])
class MFADisableView(APIView):
    """
    Disable MFA on the user's account.
    Requires password and current TOTP code for security.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = MFADisableSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user

        if not user.mfa_enabled:
            return Response(
                {"error": "MFA is not enabled."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Verify password
        if not user.check_password(serializer.validated_data["password"]):
            return Response(
                {"error": "Incorrect password."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Verify TOTP code
        try:
            device = TOTPDevice.objects.get(user=user, is_confirmed=True)
        except TOTPDevice.DoesNotExist:
            return Response(
                {"error": "MFA device not found."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not device.verify_code(serializer.validated_data["code"]):
            return Response(
                {"error": "Invalid TOTP code."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Disable MFA
        device.delete()
        user.mfa_enabled = False
        user.save(update_fields=["mfa_enabled", "updated_at"])

        log_activity(
            user=user,
            activity_type=UserActivity.ActivityType.MFA_DISABLE,
            description="Two-factor authentication disabled",
            request=request,
        )

        return Response(
            {"message": "MFA has been disabled."},
            status=status.HTTP_200_OK,
        )


@extend_schema(tags=["MFA"])
class MFAStatusView(APIView):
    """Check the current MFA status for the authenticated user."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user

        try:
            device = TOTPDevice.objects.get(user=user)
            return Response({
                "mfa_enabled": user.mfa_enabled,
                "is_confirmed": device.is_confirmed,
                "backup_codes_remaining": len(device.backup_codes),
                "last_used_at": device.last_used_at,
            })
        except TOTPDevice.DoesNotExist:
            return Response({
                "mfa_enabled": False,
                "is_confirmed": False,
                "backup_codes_remaining": 0,
                "last_used_at": None,
            })


@extend_schema(tags=["MFA"])
class MFARegenerateBackupCodesView(APIView):
    """Regenerate backup codes (invalidates old ones)."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user

        if not user.mfa_enabled:
            return Response(
                {"error": "MFA is not enabled."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            device = TOTPDevice.objects.get(user=user, is_confirmed=True)
        except TOTPDevice.DoesNotExist:
            return Response(
                {"error": "MFA device not found."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        new_codes = TOTPDevice.generate_backup_codes()
        device.backup_codes = new_codes
        device.save(update_fields=["backup_codes"])

        return Response(
            {
                "backup_codes": new_codes,
                "message": "New backup codes generated. Old codes are now invalid.",
            },
            status=status.HTTP_200_OK,
        )
