"""
Device Tracking Middleware
===========================
Automatically track devices and sessions for authenticated users.
"""

import hashlib
import logging

from apps.accounts.utils import get_client_ip, get_user_agent

logger = logging.getLogger(__name__)


class DeviceTrackingMiddleware:
    """
    Track user sessions and device information on each request.
    Creates or updates session records for authenticated users.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Only track authenticated users making API requests
        if (
            hasattr(request, "user")
            and request.user.is_authenticated
            and request.path.startswith("/api/")
        ):
            self._track_session(request)

        return response

    def _track_session(self, request):
        """Create or update a session record."""
        try:
            from .models import UserSession

            ip = get_client_ip(request)
            ua_string = get_user_agent(request)

            # Generate a session key from user + IP + user agent
            raw = f"{request.user.id}:{ip}:{ua_string}"
            session_key = hashlib.sha256(raw.encode()).hexdigest()[:64]

            # Parse user agent
            device_info = self._parse_user_agent(ua_string)

            UserSession.objects.update_or_create(
                session_key=session_key,
                defaults={
                    "user": request.user,
                    "ip_address": ip or "0.0.0.0",
                    "user_agent": ua_string[:500],
                    "device_type": device_info.get("device_type", ""),
                    "device_name": device_info.get("device_name", ""),
                    "browser": device_info.get("browser", ""),
                    "os": device_info.get("os", ""),
                    "is_active": True,
                },
            )
        except Exception as e:
            # Never let session tracking break the request
            logger.debug(f"Session tracking error: {e}")

    @staticmethod
    def _parse_user_agent(ua_string):
        """Parse user agent string into device information."""
        try:
            from user_agents import parse

            ua = parse(ua_string)
            return {
                "device_type": (
                    "mobile" if ua.is_mobile
                    else "tablet" if ua.is_tablet
                    else "bot" if ua.is_bot
                    else "pc"
                ),
                "device_name": str(ua.device.family or ""),
                "browser": f"{ua.browser.family} {ua.browser.version_string}".strip(),
                "os": f"{ua.os.family} {ua.os.version_string}".strip(),
            }
        except ImportError:
            return {
                "device_type": "unknown",
                "device_name": "",
                "browser": "",
                "os": "",
            }
