<p align="center">
  <img src="https://img.shields.io/badge/Django-5.1-092E20?style=for-the-badge&logo=django&logoColor=white" alt="Django">
  <img src="https://img.shields.io/badge/DRF-3.15-ff1709?style=for-the-badge&logo=django&logoColor=white" alt="DRF">
  <img src="https://img.shields.io/badge/PostgreSQL-16-336791?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL">
  <img src="https://img.shields.io/badge/Redis-7-DC382D?style=for-the-badge&logo=redis&logoColor=white" alt="Redis">
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

<h1 align="center">🏰 Auth Fortress</h1>

<p align="center">
  <strong>Production-grade Authentication & Authorization API</strong><br>
  Built with Django REST Framework — JWT, OAuth2, 2FA, RBAC, API Keys & more
</p>

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **🔐 JWT Authentication** | Access & refresh tokens with rotation and blacklisting |
| **🌐 OAuth2 Social Login** | Google & GitHub login with automatic account linking |
| **🛡️ Two-Factor Auth (2FA)** | TOTP-based MFA with QR codes and backup codes |
| **👥 RBAC** | Role-Based Access Control — Admin, Manager, Moderator, User |
| **🔑 API Key Management** | Create, scope, and revoke API keys for third-party access |
| **📱 Session Management** | Track active sessions and devices, sign out remotely |
| **🚫 Brute-Force Protection** | Auto-lockout after failed attempts with django-axes |
| **📧 Email Verification** | Mandatory email verification with token-based links |
| **🔄 Password Reset** | Secure token-based password reset via email |
| **📊 Activity Logging** | Full audit trail of all user actions |
| **📖 Auto API Docs** | Swagger UI & ReDoc via drf-spectacular |
| **🐳 Docker Ready** | One-command setup with docker-compose |
| **⚙️ CI/CD** | GitHub Actions pipeline with lint, test, and security scanning |

## 🏗️ Architecture

```
auth-fortress/
├── config/                  # Django project configuration
│   ├── settings.py         # Production-ready settings
│   ├── urls.py             # API URL routing
│   └── wsgi.py / asgi.py   # Server entry points
├── apps/
│   ├── accounts/           # User model, RBAC, profile, admin
│   ├── authentication/     # JWT login, logout, token refresh
│   ├── oauth/              # Google & GitHub OAuth2
│   ├── mfa/                # TOTP 2FA with QR codes
│   ├── api_keys/           # API key CRUD & authentication
│   └── sessions/           # Device tracking & session management
├── tests/                  # Comprehensive test suite
├── .github/workflows/      # CI/CD pipeline
├── Dockerfile             # Production Docker image
└── docker-compose.yml     # Full stack (Django + PostgreSQL + Redis)
```

## 🚀 Quick Start

### Prerequisites
- Python 3.12+
- PostgreSQL 16+
- Redis 7+
- Docker & Docker Compose (optional)

### Option 1: Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/django-auth-fortress.git
cd django-auth-fortress

# Copy environment file
cp .env.example .env

# Start everything
docker-compose up -d

# Create superuser
docker-compose exec web python manage.py createsuperuser

# Access the API docs
open http://localhost:8000/api/docs/
```

### Option 2: Local Development

```bash
# Clone and navigate
git clone https://github.com/YOUR_USERNAME/django-auth-fortress.git
cd django-auth-fortress

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Setup environment
cp .env.example .env
# Edit .env with your database credentials

# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Start the server
python manage.py runserver
```

## 📚 API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/auth/register/` | Register new account |
| `POST` | `/api/v1/auth/login/` | Login (returns JWT) |
| `POST` | `/api/v1/auth/logout/` | Logout (blacklist token) |
| `POST` | `/api/v1/auth/token/refresh/` | Refresh access token |
| `POST` | `/api/v1/auth/verify-email/` | Verify email address |
| `POST` | `/api/v1/auth/password/reset/` | Request password reset |
| `POST` | `/api/v1/auth/password/reset/confirm/` | Confirm password reset |
| `GET`  | `/api/v1/auth/me/` | Get current user info |

### User Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET/PUT/PATCH` | `/api/v1/users/profile/` | User profile |
| `POST` | `/api/v1/users/change-password/` | Change password |
| `GET`  | `/api/v1/users/activity/` | Activity log |
| `GET`  | `/api/v1/users/admin/` | List users (Admin) |
| `GET/PUT/DELETE` | `/api/v1/users/admin/<id>/` | Manage user (Admin) |
| `PATCH` | `/api/v1/users/admin/<id>/role/` | Update role (Admin) |
| `POST` | `/api/v1/users/admin/<id>/unlock/` | Unlock account (Admin) |

### OAuth2 Social Login
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/v1/oauth/providers/` | List OAuth providers |
| `POST` | `/api/v1/oauth/google/` | Google login |
| `POST` | `/api/v1/oauth/github/` | GitHub login |

### Multi-Factor Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/mfa/setup/` | Initialize MFA setup |
| `POST` | `/api/v1/mfa/confirm/` | Confirm MFA with TOTP code |
| `POST` | `/api/v1/mfa/verify/` | Verify MFA during login |
| `POST` | `/api/v1/mfa/disable/` | Disable MFA |
| `GET`  | `/api/v1/mfa/status/` | Check MFA status |
| `POST` | `/api/v1/mfa/backup-codes/regenerate/` | Regenerate backup codes |

### API Keys
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/v1/api-keys/` | List API keys |
| `POST` | `/api/v1/api-keys/` | Create new API key |
| `GET`  | `/api/v1/api-keys/<id>/` | Get API key details |
| `DELETE` | `/api/v1/api-keys/<id>/` | Revoke API key |

### Sessions
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/v1/sessions/` | List active sessions |
| `DELETE` | `/api/v1/sessions/<id>/terminate/` | Terminate session |
| `POST` | `/api/v1/sessions/terminate-all/` | Sign out everywhere |

### API Documentation
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/docs/` | Swagger UI |
| `GET`  | `/api/redoc/` | ReDoc |
| `GET`  | `/api/schema/` | OpenAPI schema |

## 🔒 Security Features

- **Argon2 password hashing** (strongest available)
- **JWT token rotation** with blacklisting
- **TOTP-based 2FA** with backup codes
- **Brute-force protection** via django-axes (5 attempts → 30min lockout)
- **Rate limiting** on sensitive endpoints
- **Security headers** (HSTS, XSS, Content-Type, Frame Options)
- **CORS** configuration
- **API key hashing** (raw key never stored)
- **Audit logging** of all security events
- **Session/device tracking** with remote termination

## 🧪 Running Tests

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=apps --cov-report=html

# Run specific test class
pytest tests/test_auth.py::TestLogin

# Run excluding slow tests
pytest -m "not slow"
```

## 🛠️ Tech Stack

| Technology | Purpose |
|-----------|---------|
| **Django 5.1** | Web framework |
| **Django REST Framework** | API layer |
| **SimpleJWT** | JWT token management |
| **django-allauth** | OAuth2 social authentication |
| **django-axes** | Brute-force protection |
| **pyotp + qrcode** | TOTP 2FA implementation |
| **PostgreSQL** | Primary database |
| **Redis** | Caching & Celery broker |
| **Celery** | Async task processing |
| **Docker** | Containerization |
| **GitHub Actions** | CI/CD pipeline |
| **drf-spectacular** | API documentation |
| **pytest** | Test framework |

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <strong>Built with ❤️ for production-grade security</strong>
</p>
