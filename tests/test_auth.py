"""
Authentication Tests
======================
Comprehensive tests for registration, login, logout, and token operations.
"""

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from .factories import UserFactory

User = get_user_model()


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def user():
    return UserFactory()


@pytest.fixture
def admin_user():
    return UserFactory(admin=True)


@pytest.fixture
def authenticated_client(api_client, user):
    api_client.force_authenticate(user=user)
    return api_client


@pytest.fixture
def admin_client(api_client, admin_user):
    api_client.force_authenticate(user=admin_user)
    return api_client


# ─── Registration Tests ──────────────────────────────────────


@pytest.mark.django_db
class TestRegistration:
    """Test user registration endpoints."""

    def test_register_success(self, api_client):
        """Test successful user registration."""
        data = {
            "email": "newuser@example.com",
            "first_name": "John",
            "last_name": "Doe",
            "password": "SecureP@ss123!",
            "password_confirm": "SecureP@ss123!",
        }
        response = api_client.post(
            reverse("authentication:register"),
            data,
            format="json",
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert "user" in response.data
        assert response.data["user"]["email"] == "newuser@example.com"
        assert User.objects.filter(email="newuser@example.com").exists()

    def test_register_password_mismatch(self, api_client):
        """Test registration fails with mismatched passwords."""
        data = {
            "email": "newuser@example.com",
            "first_name": "John",
            "last_name": "Doe",
            "password": "SecureP@ss123!",
            "password_confirm": "DifferentPass456!",
        }
        response = api_client.post(
            reverse("authentication:register"),
            data,
            format="json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_register_duplicate_email(self, api_client, user):
        """Test registration fails with duplicate email."""
        data = {
            "email": user.email,
            "first_name": "John",
            "last_name": "Doe",
            "password": "SecureP@ss123!",
            "password_confirm": "SecureP@ss123!",
        }
        response = api_client.post(
            reverse("authentication:register"),
            data,
            format="json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_register_weak_password(self, api_client):
        """Test registration fails with weak password."""
        data = {
            "email": "newuser@example.com",
            "first_name": "John",
            "last_name": "Doe",
            "password": "123",
            "password_confirm": "123",
        }
        response = api_client.post(
            reverse("authentication:register"),
            data,
            format="json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST


# ─── Login Tests ──────────────────────────────────────────────


@pytest.mark.django_db
class TestLogin:
    """Test JWT login endpoints."""

    def test_login_success(self, api_client, user):
        """Test successful login returns JWT tokens."""
        response = api_client.post(
            reverse("authentication:login"),
            {"email": user.email, "password": "TestPass123!"},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data
        assert "refresh" in response.data
        assert "user" in response.data
        assert response.data["user"]["email"] == user.email

    def test_login_wrong_password(self, api_client, user):
        """Test login fails with wrong password."""
        response = api_client.post(
            reverse("authentication:login"),
            {"email": user.email, "password": "WrongPassword!"},
            format="json",
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_login_nonexistent_user(self, api_client):
        """Test login fails for non-existent email."""
        response = api_client.post(
            reverse("authentication:login"),
            {"email": "nobody@example.com", "password": "TestPass123!"},
            format="json",
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


# ─── Logout Tests ─────────────────────────────────────────────


@pytest.mark.django_db
class TestLogout:
    """Test logout (token blacklisting)."""

    def test_logout_success(self, api_client, user):
        """Test successful logout blacklists the refresh token."""
        # Login first
        login_response = api_client.post(
            reverse("authentication:login"),
            {"email": user.email, "password": "TestPass123!"},
            format="json",
        )
        refresh_token = login_response.data["refresh"]
        access_token = login_response.data["access"]

        # Logout
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
        response = api_client.post(
            reverse("authentication:logout"),
            {"refresh": refresh_token},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK

    def test_logout_unauthenticated(self, api_client):
        """Test logout fails without authentication."""
        response = api_client.post(
            reverse("authentication:logout"),
            {"refresh": "fake-token"},
            format="json",
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


# ─── WhoAmI Tests ─────────────────────────────────────────────


@pytest.mark.django_db
class TestWhoAmI:
    """Test the whoami endpoint."""

    def test_whoami_authenticated(self, authenticated_client, user):
        """Test whoami returns current user info."""
        response = authenticated_client.get(reverse("authentication:whoami"))
        assert response.status_code == status.HTTP_200_OK
        assert response.data["email"] == user.email
        assert response.data["role"] == user.role

    def test_whoami_unauthenticated(self, api_client):
        """Test whoami fails without authentication."""
        response = api_client.get(reverse("authentication:whoami"))
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


# ─── Profile Tests ────────────────────────────────────────────


@pytest.mark.django_db
class TestProfile:
    """Test user profile endpoints."""

    def test_get_profile(self, authenticated_client, user):
        """Test getting user profile."""
        response = authenticated_client.get(reverse("accounts:profile"))
        assert response.status_code == status.HTTP_200_OK
        assert response.data["email"] == user.email

    def test_update_profile(self, authenticated_client, user):
        """Test updating user profile."""
        response = authenticated_client.patch(
            reverse("accounts:profile"),
            {"first_name": "Updated", "bio": "New bio"},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        user.refresh_from_db()
        assert user.first_name == "Updated"
        assert user.bio == "New bio"

    def test_cannot_update_email_via_profile(self, authenticated_client, user):
        """Test that email cannot be changed via profile update."""
        original_email = user.email
        authenticated_client.patch(
            reverse("accounts:profile"),
            {"email": "hacker@example.com"},
            format="json",
        )
        user.refresh_from_db()
        assert user.email == original_email


# ─── Password Change Tests ───────────────────────────────────


@pytest.mark.django_db
class TestPasswordChange:
    """Test password change functionality."""

    def test_change_password_success(self, authenticated_client, user):
        """Test successful password change."""
        response = authenticated_client.post(
            reverse("accounts:change-password"),
            {
                "old_password": "TestPass123!",
                "new_password": "NewSecureP@ss456!",
                "new_password_confirm": "NewSecureP@ss456!",
            },
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK

    def test_change_password_wrong_old(self, authenticated_client):
        """Test password change fails with wrong current password."""
        response = authenticated_client.post(
            reverse("accounts:change-password"),
            {
                "old_password": "WrongPassword!",
                "new_password": "NewSecureP@ss456!",
                "new_password_confirm": "NewSecureP@ss456!",
            },
            format="json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST


# ─── Admin Tests ──────────────────────────────────────────────


@pytest.mark.django_db
class TestAdminEndpoints:
    """Test admin-only endpoints."""

    def test_admin_list_users(self, admin_client):
        """Test admin can list all users."""
        UserFactory.create_batch(5)
        response = admin_client.get(reverse("accounts:admin-user-list"))
        assert response.status_code == status.HTTP_200_OK

    def test_regular_user_cannot_list_users(self, authenticated_client):
        """Test regular user cannot access admin endpoints."""
        response = authenticated_client.get(reverse("accounts:admin-user-list"))
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_admin_update_role(self, admin_client, user):
        """Test admin can update user roles."""
        response = admin_client.patch(
            reverse("accounts:admin-role-update", kwargs={"user_id": user.id}),
            {"role": "manager"},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        user.refresh_from_db()
        assert user.role == "manager"

    def test_admin_unlock_account(self, admin_client, user):
        """Test admin can unlock a locked account."""
        from django.utils import timezone
        from datetime import timedelta

        user.locked_until = timezone.now() + timedelta(hours=1)
        user.failed_login_attempts = 5
        user.save()

        response = admin_client.post(
            reverse("accounts:admin-unlock", kwargs={"user_id": user.id}),
        )
        assert response.status_code == status.HTTP_200_OK
        user.refresh_from_db()
        assert user.locked_until is None
        assert user.failed_login_attempts == 0


# ─── API Key Tests ────────────────────────────────────────────


@pytest.mark.django_db
class TestAPIKeys:
    """Test API key management."""

    def test_create_api_key(self, authenticated_client):
        """Test creating an API key returns the raw key once."""
        response = authenticated_client.post(
            reverse("api_keys:list-create"),
            {"name": "Test Key", "scope": "read"},
            format="json",
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert "key" in response.data
        assert response.data["key"].startswith("af_")

    def test_list_api_keys(self, authenticated_client):
        """Test listing API keys (without raw key)."""
        # Create a key first
        authenticated_client.post(
            reverse("api_keys:list-create"),
            {"name": "Test Key", "scope": "read"},
            format="json",
        )

        response = authenticated_client.get(reverse("api_keys:list-create"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["api_keys"]) == 1
        # Raw key should NOT be in the list response
        assert "key" not in response.data["api_keys"][0]

    def test_revoke_api_key(self, authenticated_client):
        """Test revoking an API key."""
        create_response = authenticated_client.post(
            reverse("api_keys:list-create"),
            {"name": "Revoke Me", "scope": "read"},
            format="json",
        )
        key_id = create_response.data["api_key"]["id"]

        response = authenticated_client.delete(
            reverse("api_keys:detail", kwargs={"key_id": key_id}),
        )
        assert response.status_code == status.HTTP_200_OK


# ─── Model Tests ──────────────────────────────────────────────


@pytest.mark.django_db
class TestUserModel:
    """Test User model methods and properties."""

    def test_create_user(self):
        """Test creating a user with email."""
        user = User.objects.create_user(
            email="test@example.com",
            password="TestPass123!",
            first_name="Test",
            last_name="User",
        )
        assert user.email == "test@example.com"
        assert user.check_password("TestPass123!")
        assert user.role == "user"
        assert not user.is_staff
        assert not user.is_superuser

    def test_create_superuser(self):
        """Test creating a superuser."""
        admin = User.objects.create_superuser(
            email="admin@example.com",
            password="AdminPass123!",
        )
        assert admin.is_staff
        assert admin.is_superuser
        assert admin.role == "admin"

    def test_full_name(self):
        """Test full_name property."""
        user = UserFactory(first_name="John", last_name="Doe")
        assert user.full_name == "John Doe"

    def test_is_locked(self):
        """Test account locking."""
        from datetime import timedelta

        from django.utils import timezone

        user = UserFactory()
        assert not user.is_locked

        user.locked_until = timezone.now() + timedelta(hours=1)
        user.save()
        assert user.is_locked

    def test_record_failed_login_locks_account(self):
        """Test that 5 failed logins lock the account."""
        user = UserFactory()
        for _ in range(5):
            user.record_failed_login()

        user.refresh_from_db()
        assert user.failed_login_attempts == 5
        assert user.is_locked
