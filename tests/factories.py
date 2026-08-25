"""
Test Factories
===============
Factory Boy factories for generating test data.
"""

import factory
from django.contrib.auth import get_user_model
from factory.django import DjangoModelFactory

User = get_user_model()


class UserFactory(DjangoModelFactory):
    """Factory for creating test users."""

    class Meta:
        model = User
        skip_postgeneration_save = True

    email = factory.Sequence(lambda n: f"user{n}@example.com")
    first_name = factory.Faker("first_name")
    last_name = factory.Faker("last_name")
    password = factory.PostGenerationMethodCall("set_password", "TestPass123!")
    is_active = True
    is_verified = True
    role = "user"

    class Params:
        admin = factory.Trait(
            role="admin",
            is_staff=True,
            is_superuser=True,
        )
        manager = factory.Trait(role="manager")
        moderator = factory.Trait(role="moderator")
        unverified = factory.Trait(is_verified=False)
