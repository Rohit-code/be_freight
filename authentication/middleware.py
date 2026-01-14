import jwt
from django.contrib.auth import get_user_model
from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

User = get_user_model()


class JWTAuthentication(BaseAuthentication):
    """Custom JWT Authentication for DRF"""
    
    def authenticate(self, request):
        # Skip authentication for OPTIONS requests (CORS preflight)
        if request.method == 'OPTIONS':
            return None
            
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        # Return None if no Authorization header (let DRF handle permission check)
        if not auth_header or not auth_header.startswith('Bearer '):
            return None
        
        try:
            token = auth_header.split(' ')[1]
            if not token or token.strip() == '':
                return None
        except IndexError:
            return None
        
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = payload.get('user_id')
            
            if user_id:
                user = User.objects.get(id=user_id)
                return (user, None)
            return None
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        except User.DoesNotExist:
            return None
        except Exception as e:
            print(f"[ERROR] JWTAuthentication: {str(e)}")
            return None
        
        return None
