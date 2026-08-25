"""
Session & Device Models
========================
Track active sessions and device fingerprints for security.
"""

import uuid

from django.conf import settings
from django.db import models


class UserSession(models.Model):
    """
    Track active user sessions with device information.
    Enables "sign out from all devices" and suspicious session detection.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="sessions",
    )
    session_key = models.CharField(max_length=64, unique=True, db_index=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)

    # Parsed device info
    device_type = models.CharField(max_length=20, blank=True)  # mobile, tablet, pc, bot
    device_name = models.CharField(max_length=100, blank=True)  # e.g., "iPhone 15"
    browser = models.CharField(max_length=100, blank=True)  # e.g., "Chrome 120"
    os = models.CharField(max_length=100, blank=True)  # e.g., "Windows 11"

    # Location (from IP)
    country = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)

    is_active = models.BooleanField(default=True)
    is_current = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    expired_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "user_sessions"
        verbose_name = "User Session"
        verbose_name_plural = "User Sessions"
        ordering = ["-last_activity"]
        indexes = [
            models.Index(fields=["user", "is_active"], name="idx_session_user_active"),
            models.Index(fields=["session_key"], name="idx_session_key"),
        ]

    def __str__(self):
        return f"{self.user.email} — {self.device_name or self.browser} ({self.ip_address})"

    def terminate(self):
        """Terminate this session."""
        from django.utils import timezone

        self.is_active = False
        self.expired_at = timezone.now()
        self.save(update_fields=["is_active", "expired_at"])
