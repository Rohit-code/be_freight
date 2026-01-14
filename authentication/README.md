# Authentication App

This Django app handles all authentication-related functionality including email/password login and Google OAuth authentication.

## Features

- ✅ Custom User model extending Django's AbstractUser
- ✅ Email/Password authentication
- ✅ Google OAuth authentication
- ✅ JWT token-based authentication
- ✅ RESTful API endpoints
- ✅ CORS support for frontend integration

## API Endpoints

### Authentication Endpoints

- `POST /api/auth/login` - Email/password login
  - Body: `{ "email": "user@example.com", "password": "password123" }`
  - Response: `{ "user": {...}, "token": "jwt_token" }`

- `POST /api/auth/google/verify` - Google OAuth verification
  - Body: `{ "credential": "google_jwt_token" }`
  - Response: `{ "user": {...}, "token": "jwt_token" }`

- `GET /api/auth/me` - Get current authenticated user
  - Headers: `Authorization: Bearer <token>`
  - Response: `{ "user": {...}, "token": "jwt_token" }`

- `POST /api/auth/logout` - Logout (client should discard token)
  - Headers: `Authorization: Bearer <token>`
  - Response: `{ "message": "Successfully logged out" }`

## Models

### User
Custom user model with additional fields:
- `email` - Unique email field (used as USERNAME_FIELD)
- `picture` - Profile picture URL
- `google_id` - Google user ID for OAuth users
- `is_google_user` - Boolean flag for Google OAuth users
- `created_at` - Account creation timestamp
- `updated_at` - Last update timestamp

## Authentication Flow

### Email/Password Login
1. Client sends email and password to `/api/auth/login`
2. Server validates credentials
3. Server generates JWT token
4. Server returns user data and token

### Google OAuth Login
1. Frontend uses Google Identity Services to get credential token
2. Frontend sends credential to `/api/auth/google/verify`
3. Server verifies Google token
4. Server creates or updates user account
5. Server generates JWT token
6. Server returns user data and token

### Protected Routes
- Include `Authorization: Bearer <token>` header in requests
- JWT token expires after 7 days
- Use `/api/auth/me` to verify token and get user data

## Configuration

Required environment variables in `.env`:
- `GOOGLE_CLIENT_ID` - Google OAuth Client ID
- `GOOGLE_CLIENT_SECRET` - Google OAuth Client Secret (not used in current implementation but required for future features)
- `DJANGO_SECRET_KEY` - Django secret key for JWT signing
- `DEBUG` - Debug mode (True/False)
- `ALLOWED_HOSTS` - Comma-separated list of allowed hosts

## Dependencies

- Django 6.0.1+
- Django REST Framework
- django-cors-headers
- PyJWT
- google-auth
- python-decouple
- requests

## Usage

1. Make sure migrations are applied: `python manage.py migrate`
2. Start the development server: `python manage.py runserver`
3. The API will be available at `http://localhost:8000/api/auth/`

## Testing

You can test the endpoints using curl or Postman:

```bash
# Login with email/password
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'

# Get current user (replace TOKEN with actual token)
curl -X GET http://localhost:8000/api/auth/me \
  -H "Authorization: Bearer TOKEN"
```
