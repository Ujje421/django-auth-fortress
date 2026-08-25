"""
Account URLs
=============
"""

from django.urls import path

from . import views

app_name = "accounts"

urlpatterns = [
    # Profile
    path("profile/", views.ProfileView.as_view(), name="profile"),
    path("change-password/", views.ChangePasswordView.as_view(), name="change-password"),
    path("activity/", views.ActivityLogView.as_view(), name="activity-log"),
    # Admin - User Management
    path("admin/", views.AdminUserListView.as_view(), name="admin-user-list"),
    path("admin/<uuid:id>/", views.AdminUserDetailView.as_view(), name="admin-user-detail"),
    path("admin/<uuid:user_id>/role/", views.AdminRoleUpdateView.as_view(), name="admin-role-update"),
    path("admin/<uuid:user_id>/unlock/", views.AdminUnlockAccountView.as_view(), name="admin-unlock"),
]
