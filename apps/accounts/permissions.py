"""
RBAC Permissions
=================
Role-based permission classes for the API.
"""

from rest_framework.permissions import BasePermission


class IsAdmin(BasePermission):
    """Only allow admin users."""

    message = "Admin access required."

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.role == "admin"
        )


class IsManager(BasePermission):
    """Allow admin and manager users."""

    message = "Manager access required."

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.role in ("admin", "manager")
        )


class IsModerator(BasePermission):
    """Allow admin, manager, and moderator users."""

    message = "Moderator access required."

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.role in ("admin", "manager", "moderator")
        )


class IsOwnerOrAdmin(BasePermission):
    """Allow object owner or admin."""

    message = "You can only access your own resources."

    def has_object_permission(self, request, view, obj):
        if request.user.role == "admin":
            return True
        return obj == request.user or getattr(obj, "user", None) == request.user


class IsVerified(BasePermission):
    """Only allow users with verified email."""

    message = "Email verification required."

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.is_verified
        )


class IsNotLocked(BasePermission):
    """Deny access to locked accounts."""

    message = "Account is temporarily locked due to too many failed login attempts."

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and not request.user.is_locked
        )
