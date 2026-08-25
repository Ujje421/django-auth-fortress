"""
API Key Models
===============
Secure API key management for third-party integrations.
"""

import hashlib
import secrets
import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class APIKey(models.Model):
    """
    API Key for programmatic access.
    The raw key is only shown once at creation — only the hash is stored.
    """

    class Scope(models.TextChoices):
        READ = "read", "Read Only"
        WRITE = "write", "Read & Write"
        ADMIN = "admin", "Full Admin Access"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="api_keys",
    )
    name = models.CharField(max_length=100, help_text="A label for this API key")
    prefix = models.CharField(
        max_length=8,
        db_index=True,
        help_text="First 8 chars of the key for identification",
    )
    key_hash = models.CharField(max_length=128, unique=True)
    scope = models.CharField(
        max_length=10,
        choices=Scope.choices,
        default=Scope.READ,
    )
    is_active = models.BooleanField(default=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    last_used_ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "api_keys"
        verbose_name = "API Key"
        verbose_name_plural = "API Keys"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.name} ({self.prefix}...)"

    @classmethod
    def create_key(cls, user, name, scope="read", expires_at=None):
        """
        Generate a new API key. Returns (api_key_instance, raw_key).
        The raw key is only available at creation time.
        """
        raw_key = f"af_{secrets.token_urlsafe(48)}"
        prefix = raw_key[:8]
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        api_key = cls.objects.create(
            user=user,
            name=name,
            prefix=prefix,
            key_hash=key_hash,
            scope=scope,
            expires_at=expires_at,
        )

        return api_key, raw_key

    @classmethod
    def verify_key(cls, raw_key):
        """
        Verify an API key and return the associated key object.
        Returns None if the key is invalid, expired, or revoked.
        """
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        try:
            api_key = cls.objects.select_related("user").get(
                key_hash=key_hash,
                is_active=True,
            )
        except cls.DoesNotExist:
            return None

        # Check expiration
        if api_key.expires_at and api_key.expires_at < timezone.now():
            return None

        return api_key

    def record_usage(self, ip_address=None):
        """Record API key usage."""
        self.last_used_at = timezone.now()
        self.last_used_ip = ip_address
        self.save(update_fields=["last_used_at", "last_used_ip"])

    def revoke(self):
        """Revoke this API key."""
        self.is_active = False
        self.revoked_at = timezone.now()
        self.save(update_fields=["is_active", "revoked_at"])

    @property
    def is_expired(self):
        if self.expires_at and self.expires_at < timezone.now():
            return True
        return False
