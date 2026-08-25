"""
MFA Serializers
================
"""

from rest_framework import serializers


class MFASetupSerializer(serializers.Serializer):
    """Response serializer for MFA setup."""

    secret = serializers.CharField(read_only=True)
    provisioning_uri = serializers.CharField(read_only=True)
    qr_code = serializers.CharField(read_only=True, help_text="Base64 encoded QR code image")
    backup_codes = serializers.ListField(child=serializers.CharField(), read_only=True)


class MFAConfirmSerializer(serializers.Serializer):
    """Confirm MFA setup with a TOTP code."""

    code = serializers.CharField(
        min_length=6,
        max_length=6,
        required=True,
        help_text="6-digit TOTP code from authenticator app",
    )


class MFAVerifySerializer(serializers.Serializer):
    """Verify MFA during login."""

    mfa_token = serializers.CharField(required=True, help_text="Temporary token from login")
    code = serializers.CharField(
        min_length=6,
        max_length=8,
        required=True,
        help_text="6-digit TOTP code or backup code",
    )


class MFADisableSerializer(serializers.Serializer):
    """Disable MFA with password confirmation."""

    password = serializers.CharField(
        required=True,
        style={"input_type": "password"},
    )
    code = serializers.CharField(
        min_length=6,
        max_length=6,
        required=True,
        help_text="Current 6-digit TOTP code",
    )
