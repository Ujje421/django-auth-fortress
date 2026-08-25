"""Sessions URL Configuration"""

from django.urls import path

from . import views

app_name = "sessions"

urlpatterns = [
    path("", views.ActiveSessionsView.as_view(), name="active-sessions"),
    path("<uuid:session_id>/terminate/", views.TerminateSessionView.as_view(), name="terminate-session"),
    path("terminate-all/", views.TerminateAllSessionsView.as_view(), name="terminate-all"),
]
