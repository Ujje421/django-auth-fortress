"""API Keys URL Configuration"""

from django.urls import path

from . import views

app_name = "api_keys"

urlpatterns = [
    path("", views.APIKeyListCreateView.as_view(), name="list-create"),
    path("<uuid:key_id>/", views.APIKeyDetailView.as_view(), name="detail"),
]
