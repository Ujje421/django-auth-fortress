"""
MFA Models
===========
TOTP secret storage for two-factor authentication.
"""

import uuid

import pyotp
from django.conf import settings
from django.db import models


class TOTPDevice(models.Model):
    """
    Stores a TOTP secret for a user.
    Each user can have one active TOTP device.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="totp_device",
    )
    secret = models.CharField(max_length=64)
    is_confirmed = models.BooleanField(default=False)
    backup_codes = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "totp_devices"
        verbose_name = "TOTP Device"
        verbose_name_plural = "TOTP Devices"

    def __str__(self):
        return f"TOTP for {self.user.email}"

    @classmethod
    def create_for_user(cls, user):
        """Create a new TOTP device with a fresh secret."""
        secret = pyotp.random_base32()
        backup_codes = cls.generate_backup_codes()
        device, _ = cls.objects.update_or_create(
            user=user,
            defaults={
                "secret": secret,
                "is_confirmed": False,
                "backup_codes": backup_codes,
            },
        )
        return device

    @staticmethod
    def generate_backup_codes(count=10):
        """Generate one-time backup codes."""
        import secrets

        return [secrets.token_hex(4).upper() for _ in range(count)]

    def get_totp(self):
        """Get the TOTP instance."""
        return pyotp.TOTP(self.secret)

    def verify_code(self, code):
        """Verify a TOTP code (with 30-second window tolerance)."""
        totp = self.get_totp()
        return totp.verify(code, valid_window=1)

    def verify_backup_code(self, code):
        """Verify and consume a backup code."""
        code_upper = code.upper()
        if code_upper in self.backup_codes:
            self.backup_codes.remove(code_upper)
            self.save(update_fields=["backup_codes"])
            return True
        return False

    def get_provisioning_uri(self):
        """Get the otpauth:// URI for QR code generation."""
        totp = self.get_totp()
        return totp.provisioning_uri(
            name=self.user.email,
            issuer_name="Auth Fortress",
        )
