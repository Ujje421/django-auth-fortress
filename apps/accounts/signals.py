"""
Signals
========
Post-save and post-login signals for user account events.
"""

import logging

from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import UserActivity
from .utils import get_client_ip, get_user_agent, log_activity

logger = logging.getLogger(__name__)
User = get_user_model()


@receiver(user_logged_in)
def on_user_login(sender, request, user, **kwargs):
    """Log successful login and update user metadata."""
    ip_address = get_client_ip(request) if request else None
    user.record_login(ip_address=ip_address)

    log_activity(
        user=user,
        activity_type=UserActivity.ActivityType.LOGIN,
        description="User logged in",
        request=request,
        metadata={"method": "credentials"},
    )
    logger.info(f"User logged in: {user.email} from {ip_address}")


@receiver(user_login_failed)
def on_user_login_failed(sender, credentials, request, **kwargs):
    """Log failed login attempts."""
    email = credentials.get("email", credentials.get("username", "unknown"))
    ip_address = get_client_ip(request) if request else None

    try:
        user = User.objects.get(email=email)
        user.record_failed_login()
        logger.warning(
            f"Failed login attempt for {email} from {ip_address}. "
            f"Attempts: {user.failed_login_attempts}"
        )
    except User.DoesNotExist:
        logger.warning(f"Failed login attempt for non-existent user: {email}")
