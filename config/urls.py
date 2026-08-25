"""
Auth Fortress — URL Configuration
==================================
"""

from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

urlpatterns = [
    # Admin
    path("admin/", admin.site.urls),
    # API Documentation
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    path("api/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
    # API v1
    path("api/v1/auth/", include("apps.authentication.urls")),
    path("api/v1/users/", include("apps.accounts.urls")),
    path("api/v1/oauth/", include("apps.oauth.urls")),
    path("api/v1/mfa/", include("apps.mfa.urls")),
    path("api/v1/api-keys/", include("apps.api_keys.urls")),
    path("api/v1/sessions/", include("apps.sessions.urls")),
]
