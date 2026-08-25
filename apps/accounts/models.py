"""
User Models
============
Custom User model with RBAC support, profile, and audit fields.
"""

import uuid

from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from django.utils import timezone

from .managers import UserManager


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom User model using email as the primary identifier.
    Includes role-based access control and comprehensive profile fields.
    """

    class Role(models.TextChoices):
        ADMIN = "admin", "Administrator"
        MANAGER = "manager", "Manager"
        MODERATOR = "moderator", "Moderator"
        USER = "user", "User"

    # ─── Primary Fields ──────────────────────────────────────
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(
        unique=True,
        max_length=255,
        db_index=True,
        error_messages={"unique": "A user with that email already exists."},
    )

    # ─── Profile Fields ─────────────────────────────────────
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    avatar = models.ImageField(upload_to="avatars/%Y/%m/", blank=True, null=True)
    phone_number = models.CharField(max_length=20, blank=True)
    bio = models.TextField(max_length=500, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)

    # ─── RBAC ────────────────────────────────────────────────
    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.USER,
        db_index=True,
    )

    # ─── Status & Verification ───────────────────────────────
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    email_verified_at = models.DateTimeField(null=True, blank=True)

    # ─── Security ────────────────────────────────────────────
    mfa_enabled = models.BooleanField(default=False)
    password_changed_at = models.DateTimeField(null=True, blank=True)
    failed_login_attempts = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)

    # ─── Audit Fields ────────────────────────────────────────
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    last_active_at = models.DateTimeField(null=True, blank=True)

    # ─── Manager ─────────────────────────────────────────────
    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]

    class Meta:
        db_table = "users"
        verbose_name = "user"
        verbose_name_plural = "users"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["email"], name="idx_user_email"),
            models.Index(fields=["role"], name="idx_user_role"),
            models.Index(fields=["created_at"], name="idx_user_created"),
            models.Index(fields=["is_active", "is_verified"], name="idx_user_status"),
        ]

    def __str__(self):
        return self.email

    @property
    def full_name(self):
        """Return the user's full name."""
        return f"{self.first_name} {self.last_name}".strip() or self.email

    @property
    def is_admin(self):
        return self.role == self.Role.ADMIN

    @property
    def is_manager(self):
        return self.role in (self.Role.ADMIN, self.Role.MANAGER)

    @property
    def is_moderator(self):
        return self.role in (self.Role.ADMIN, self.Role.MANAGER, self.Role.MODERATOR)

    @property
    def is_locked(self):
        """Check if the account is currently locked."""
        if self.locked_until and self.locked_until > timezone.now():
            return True
        return False

    def verify_email(self):
        """Mark the user's email as verified."""
        self.is_verified = True
        self.email_verified_at = timezone.now()
        self.save(update_fields=["is_verified", "email_verified_at", "updated_at"])

    def record_login(self, ip_address=None):
        """Record a successful login."""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login_ip = ip_address
        self.last_active_at = timezone.now()
        self.save(
            update_fields=[
                "failed_login_attempts",
                "locked_until",
                "last_login_ip",
                "last_active_at",
                "updated_at",
            ]
        )

    def record_failed_login(self):
        """Record a failed login attempt and lock if threshold exceeded."""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.locked_until = timezone.now() + timezone.timedelta(minutes=30)
        self.save(update_fields=["failed_login_attempts", "locked_until", "updated_at"])


class UserActivity(models.Model):
    """Audit log for user activities."""

    class ActivityType(models.TextChoices):
        LOGIN = "login", "Login"
        LOGOUT = "logout", "Logout"
        PASSWORD_CHANGE = "password_change", "Password Change"
        PASSWORD_RESET = "password_reset", "Password Reset"
        EMAIL_CHANGE = "email_change", "Email Change"
        MFA_ENABLE = "mfa_enable", "MFA Enabled"
        MFA_DISABLE = "mfa_disable", "MFA Disabled"
        PROFILE_UPDATE = "profile_update", "Profile Update"
        API_KEY_CREATE = "api_key_create", "API Key Created"
        API_KEY_REVOKE = "api_key_revoke", "API Key Revoked"
        ACCOUNT_LOCK = "account_lock", "Account Locked"
        ACCOUNT_UNLOCK = "account_unlock", "Account Unlocked"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="activities",
    )
    activity_type = models.CharField(max_length=30, choices=ActivityType.choices)
    description = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "user_activities"
        verbose_name = "user activity"
        verbose_name_plural = "user activities"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "-created_at"], name="idx_activity_user"),
            models.Index(fields=["activity_type"], name="idx_activity_type"),
        ]

    def __str__(self):
        return f"{self.user.email} — {self.activity_type} at {self.created_at}"
