"""
API Key Authentication Backend
================================
Custom DRF authentication class for API key-based access.
"""

from rest_framework import authentication, exceptions

from apps.accounts.utils import get_client_ip

from .models import APIKey


class APIKeyAuthentication(authentication.BaseAuthentication):
    """
    Authenticate requests using API keys passed in the X-API-Key header.

    Usage:
        X-API-Key: af_xxxxxxxxxxxxxxxxxxxxx
    """

    keyword = "X-API-Key"

    def authenticate(self, request):
        api_key = request.META.get("HTTP_X_API_KEY")

        if not api_key:
            return None  # Not using API key auth, try next backend

        key_obj = APIKey.verify_key(api_key)

        if key_obj is None:
            raise exceptions.AuthenticationFailed(
                "Invalid, expired, or revoked API key."
            )

        # Record usage
        ip_address = get_client_ip(request)
        key_obj.record_usage(ip_address=ip_address)

        # Attach the API key object to the request for scope checking
        request.api_key = key_obj

        return (key_obj.user, key_obj)

    def authenticate_header(self, request):
        return self.keyword
