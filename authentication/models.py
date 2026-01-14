from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """Custom User model extending Django's AbstractUser"""
    email = models.EmailField(unique=True)
    picture = models.URLField(blank=True, null=True)
    google_id = models.CharField(max_length=255, blank=True, null=True, unique=True)
    is_google_user = models.BooleanField(default=False)
    
    # Google OAuth tokens for API access
    google_access_token = models.TextField(blank=True, null=True, help_text="Google OAuth access token")
    google_refresh_token = models.TextField(blank=True, null=True, help_text="Google OAuth refresh token")
    google_token_expiry = models.DateTimeField(blank=True, null=True, help_text="Access token expiry time")
    
    # Google service connection flags
    gmail_connected = models.BooleanField(default=False)
    drive_connected = models.BooleanField(default=False)
    sheets_connected = models.BooleanField(default=False)
    docs_connected = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def __str__(self):
        return self.email
