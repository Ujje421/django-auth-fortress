"""
Authentication URLs
=====================
"""

from django.urls import path

from . import views
from apps.accounts.views import (
    PasswordResetConfirmView,
    PasswordResetRequestView,
    RegisterView,
)

app_name = "authentication"

urlpatterns = [
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("token/refresh/", views.TokenRefreshView.as_view(), name="token-refresh"),
    path("register/", RegisterView.as_view(), name="register"),
    path("verify-email/", views.EmailVerifyView.as_view(), name="verify-email"),
    path("password/reset/", PasswordResetRequestView.as_view(), name="password-reset"),
    path("password/reset/confirm/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
    path("me/", views.WhoAmIView.as_view(), name="whoami"),
]
