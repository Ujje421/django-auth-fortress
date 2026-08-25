"""
Utility Functions
==================
Custom exception handler, email helpers, and activity logging.
"""

import logging

from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from rest_framework.views import exception_handler

from .models import UserActivity

logger = logging.getLogger(__name__)


def custom_exception_handler(exc, context):
    """
    Custom exception handler that adds consistent error format.
    """
    response = exception_handler(exc, context)

    if response is not None:
        custom_response = {
            "success": False,
            "status_code": response.status_code,
            "errors": response.data,
        }
        response.data = custom_response

    return response


def get_client_ip(request):
    """Extract the client IP address from the request."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def get_user_agent(request):
    """Extract the user agent string from the request."""
    return request.META.get("HTTP_USER_AGENT", "")


def log_activity(user, activity_type, description="", request=None, metadata=None):
    """
    Create a user activity log entry.

    Args:
        user: The user who performed the activity.
        activity_type: The type of activity (from UserActivity.ActivityType).
        description: A human-readable description.
        request: The HTTP request (for IP and user agent extraction).
        metadata: Additional JSON metadata.
    """
    ip_address = get_client_ip(request) if request else None
    user_agent = get_user_agent(request) if request else ""

    try:
        UserActivity.objects.create(
            user=user,
            activity_type=activity_type,
            description=description,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata or {},
        )
    except Exception as e:
        logger.error(f"Failed to log activity for {user.email}: {e}")


def send_password_reset_email(user, uid, token):
    """
    Send a password reset email to the user.

    Args:
        user: The user requesting the reset.
        uid: URL-safe base64 encoded user ID.
        token: Password reset token.
    """
    reset_url = f"{settings.FRONTEND_URL}/reset-password?uid={uid}&token={token}"

    subject = "Reset Your Password — Auth Fortress"
    message = (
        f"Hi {user.first_name or 'there'},\n\n"
        f"You requested a password reset. Click the link below:\n\n"
        f"{reset_url}\n\n"
        f"This link will expire in 24 hours.\n\n"
        f"If you didn't request this, please ignore this email.\n\n"
        f"— Auth Fortress Team"
    )

    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
        logger.info(f"Password reset email sent to {user.email}")
    except Exception as e:
        logger.error(f"Failed to send password reset email to {user.email}: {e}")


def send_verification_email(user, uid, token):
    """
    Send an email verification email to the user.
    """
    verify_url = f"{settings.FRONTEND_URL}/verify-email?uid={uid}&token={token}"

    subject = "Verify Your Email — Auth Fortress"
    message = (
        f"Hi {user.first_name or 'there'},\n\n"
        f"Welcome to Auth Fortress! Please verify your email:\n\n"
        f"{verify_url}\n\n"
        f"— Auth Fortress Team"
    )

    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
        logger.info(f"Verification email sent to {user.email}")
    except Exception as e:
        logger.error(f"Failed to send verification email to {user.email}: {e}")
