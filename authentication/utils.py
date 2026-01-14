import jwt
import os
import secrets
from datetime import datetime, timedelta
from django.conf import settings
from django.core.cache import cache
from django.contrib.auth import get_user_model
from google.oauth2 import id_token
from google.auth.transport import requests
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.exceptions import RefreshError
from decouple import config as env_config

User = get_user_model()


def generate_jwt_token(user):
    """Generate JWT token for authenticated user"""
    payload = {
        'user_id': user.id,
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(days=7),
        'iat': datetime.utcnow(),
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return token


def verify_google_token(credential):
    """Verify Google OAuth token and return user info"""
    try:
        google_client_id = env_config('GOOGLE_CLIENT_ID')
        
        # Verify the token
        idinfo = id_token.verify_oauth2_token(
            credential,
            requests.Request(),
            google_client_id
        )

        # Verify the issuer
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')

        return {
            'email': idinfo['email'],
            'name': idinfo.get('name', ''),
            'picture': idinfo.get('picture', ''),
            'google_id': idinfo['sub'],
        }
    except ValueError as e:
        raise ValueError(f'Invalid Google token: {str(e)}')


def get_google_oauth_flow(request):
    """Create and return Google OAuth flow"""
    google_client_id = env_config('GOOGLE_CLIENT_ID')
    google_client_secret = env_config('GOOGLE_CLIENT_SECRET')
    redirect_uri = env_config('GOOGLE_BACKEND_CALLBACK_URL', default='http://localhost:8000/api/auth/google/callback')
    
    if not google_client_id or not google_client_secret:
        raise ValueError('Google Client ID or Secret not configured')
    
    # OAuth 2.0 scopes - minimal scopes for Gmail, Sheets, Docs, Drive APIs
    scopes = [
        'openid',
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile',
        # Gmail API - modify scope includes readonly and send
        'https://www.googleapis.com/auth/gmail.modify',
        # Google Sheets API - full access includes readonly
        'https://www.googleapis.com/auth/spreadsheets',
        # Google Docs API - full access includes readonly
        'https://www.googleapis.com/auth/documents',
        # Google Drive API - full access includes readonly and file
        'https://www.googleapis.com/auth/drive',
    ]
    
    try:
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": google_client_id,
                    "client_secret": google_client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [redirect_uri],
                }
            },
            scopes=scopes,
            redirect_uri=redirect_uri
        )
        return flow
    except Exception as e:
        print(f"[ERROR] get_google_oauth_flow: {str(e)}")
        import traceback
        traceback.print_exc()
        raise


def exchange_code_for_token(code):
    """Exchange OAuth authorization code for tokens"""
    try:
        google_client_id = env_config('GOOGLE_CLIENT_ID')
        google_client_secret = env_config('GOOGLE_CLIENT_SECRET')
        redirect_uri = env_config('GOOGLE_BACKEND_CALLBACK_URL', default='http://localhost:8000/api/auth/google/callback')
        
        # Create flow
        flow = get_google_oauth_flow(None)
        
        # Exchange code for token
        flow.fetch_token(code=code)
        
        # Get credentials
        credentials = flow.credentials
        id_token_jwt = credentials.id_token
        
        # Verify ID token
        idinfo = id_token.verify_oauth2_token(
            id_token_jwt,
            requests.Request(),
            google_client_id
        )
        
        # Verify issuer
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')
        
        # Extract access token, refresh token, and expiry
        access_token = credentials.token
        refresh_token = credentials.refresh_token
        expiry = credentials.expiry
        
        return {
            'email': idinfo['email'],
            'name': idinfo.get('name', ''),
            'picture': idinfo.get('picture', ''),
            'google_id': idinfo['sub'],
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_expiry': expiry,
        }
    except Exception as e:
        print(f"[ERROR] exchange_code_for_token: {str(e)}")
        import traceback
        traceback.print_exc()
        raise ValueError(f'Failed to exchange code for token: {str(e)}')


def get_user_google_credentials(user):
    """Get valid Google OAuth credentials for a user, refreshing if necessary"""
    if not user.google_access_token:
        raise ValueError('User does not have Google OAuth tokens')
    
    # Check if token is expired or will expire soon (within 5 minutes)
    if user.google_token_expiry:
        expiry_time = user.google_token_expiry
        if isinstance(expiry_time, str):
            expiry_time = datetime.fromisoformat(expiry_time.replace('Z', '+00:00'))
        if expiry_time <= datetime.now(expiry_time.tzinfo) + timedelta(minutes=5):
            print(f"[get_user_google_credentials] Token expired or expiring soon, refreshing...")
            refresh_user_google_token(user)
    
    credentials = Credentials(
        token=user.google_access_token,
        refresh_token=user.google_refresh_token,
        token_uri='https://oauth2.googleapis.com/token',
        client_id=env_config('GOOGLE_CLIENT_ID'),
        client_secret=env_config('GOOGLE_CLIENT_SECRET'),
    )
    
    return credentials


def refresh_user_google_token(user):
    """Refresh a user's Google OAuth access token"""
    if not user.google_refresh_token:
        raise ValueError('User does not have a refresh token')
    
    credentials = Credentials(
        token=None,
        refresh_token=user.google_refresh_token,
        token_uri='https://oauth2.googleapis.com/token',
        client_id=env_config('GOOGLE_CLIENT_ID'),
        client_secret=env_config('GOOGLE_CLIENT_SECRET'),
    )
    
    try:
        request_obj = requests.Request()
        credentials.refresh(request_obj)
        
        # Update user with new token
        user.google_access_token = credentials.token
        if credentials.expiry:
            user.google_token_expiry = credentials.expiry
        user.save()
        
        return credentials
    except RefreshError as e:
        print(f"[ERROR] refresh_user_google_token: {str(e)}")
        raise ValueError(f'Failed to refresh token: {str(e)}')


def get_gmail_service(user):
    """Get Gmail API service for a user"""
    credentials = get_user_google_credentials(user)
    return build('gmail', 'v1', credentials=credentials)


def get_sheets_service(user):
    """Get Google Sheets API service for a user"""
    credentials = get_user_google_credentials(user)
    return build('sheets', 'v4', credentials=credentials)


def get_docs_service(user):
    """Get Google Docs API service for a user"""
    credentials = get_user_google_credentials(user)
    return build('docs', 'v1', credentials=credentials)


def get_drive_service(user):
    """Get Google Drive API service for a user"""
    credentials = get_user_google_credentials(user)
    return build('drive', 'v3', credentials=credentials)
