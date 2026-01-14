from functools import wraps
from rest_framework.response import Response
from rest_framework import status


def handle_auth_errors(view_func):
    """Decorator to handle authentication errors gracefully"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        try:
            return view_func(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_401_UNAUTHORIZED
            )
    return wrapper
