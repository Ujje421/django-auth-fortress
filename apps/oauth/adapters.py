"""
OAuth Adapters
===============
Custom allauth adapters for social login integration.
"""

from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.conf import settings


class CustomAccountAdapter(DefaultAccountAdapter):
    """Custom account adapter for allauth."""

    def get_email_confirmation_url(self, request, emailconfirmation):
        """Use frontend URL for email confirmation."""
        return (
            f"{settings.FRONTEND_URL}/verify-email/"
            f"?key={emailconfirmation.key}"
        )

    def send_mail(self, template_prefix, email, context):
        """Override to customize email sending."""
        context["frontend_url"] = settings.FRONTEND_URL
        super().send_mail(template_prefix, email, context)


class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    """Custom social account adapter for OAuth providers."""

    def pre_social_login(self, request, sociallogin):
        """
        If a user with this email already exists, connect the social
        account to the existing user instead of creating a new one.
        """
        email = sociallogin.account.extra_data.get("email")
        if email:
            from django.contrib.auth import get_user_model

            User = get_user_model()
            try:
                existing_user = User.objects.get(email=email)
                sociallogin.connect(request, existing_user)
            except User.DoesNotExist:
                pass

    def save_user(self, request, sociallogin, form=None):
        """Auto-verify email for social login users."""
        user = super().save_user(request, sociallogin, form)
        user.is_verified = True
        user.save(update_fields=["is_verified"])
        return user
