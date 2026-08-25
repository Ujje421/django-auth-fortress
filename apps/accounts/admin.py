"""
User Admin
===========
Custom admin configuration for User and UserActivity models.
"""

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import UserActivity

User = get_user_model()


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Admin configuration for the custom User model."""

    list_display = [
        "email",
        "full_name",
        "role",
        "is_active",
        "is_verified",
        "mfa_enabled",
        "created_at",
    ]
    list_filter = ["role", "is_active", "is_verified", "mfa_enabled", "is_staff"]
    search_fields = ["email", "first_name", "last_name"]
    ordering = ["-created_at"]

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (
            "Personal Info",
            {"fields": ("first_name", "last_name", "avatar", "phone_number", "bio", "date_of_birth")},
        ),
        (
            "Access Control",
            {"fields": ("role", "is_active", "is_staff", "is_superuser", "is_verified")},
        ),
        (
            "Security",
            {
                "fields": (
                    "mfa_enabled",
                    "failed_login_attempts",
                    "locked_until",
                    "password_changed_at",
                ),
            },
        ),
        (
            "Activity",
            {"fields": ("last_login", "last_login_ip", "last_active_at")},
        ),
        (
            "Permissions",
            {"fields": ("groups", "user_permissions")},
        ),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "first_name",
                    "last_name",
                    "role",
                    "password1",
                    "password2",
                ),
            },
        ),
    )

    readonly_fields = [
        "created_at",
        "updated_at",
        "last_login_ip",
        "last_active_at",
        "password_changed_at",
    ]


@admin.register(UserActivity)
class UserActivityAdmin(admin.ModelAdmin):
    """Admin configuration for user activity logs."""

    list_display = ["user", "activity_type", "ip_address", "created_at"]
    list_filter = ["activity_type", "created_at"]
    search_fields = ["user__email", "description"]
    readonly_fields = [
        "user",
        "activity_type",
        "description",
        "ip_address",
        "user_agent",
        "metadata",
        "created_at",
    ]
    ordering = ["-created_at"]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
