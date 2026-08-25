"""OAuth URL Configuration"""

from django.urls import path

from . import views

app_name = "oauth"

urlpatterns = [
    path("providers/", views.OAuthProvidersView.as_view(), name="providers"),
    path("google/", views.GoogleLoginView.as_view(), name="google-login"),
    path("github/", views.GitHubLoginView.as_view(), name="github-login"),
]
