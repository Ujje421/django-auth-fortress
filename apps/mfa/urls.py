"""MFA URL Configuration"""

from django.urls import path

from . import views

app_name = "mfa"

urlpatterns = [
    path("setup/", views.MFASetupView.as_view(), name="setup"),
    path("confirm/", views.MFAConfirmView.as_view(), name="confirm"),
    path("verify/", views.MFAVerifyView.as_view(), name="verify"),
    path("disable/", views.MFADisableView.as_view(), name="disable"),
    path("status/", views.MFAStatusView.as_view(), name="status"),
    path("backup-codes/regenerate/", views.MFARegenerateBackupCodesView.as_view(), name="regenerate-backup-codes"),
]
