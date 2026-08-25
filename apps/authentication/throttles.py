"""
Custom Throttles
=================
Rate limiting for sensitive authentication endpoints.
"""

from rest_framework.throttling import AnonRateThrottle


class LoginRateThrottle(AnonRateThrottle):
    """Strict rate limiting for login attempts."""

    scope = "login"
