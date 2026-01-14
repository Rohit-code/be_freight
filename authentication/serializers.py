from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import User


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model"""
    has_google_connected = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'first_name', 'last_name', 'picture', 'is_google_user', 'has_google_connected')
        read_only_fields = ('id', 'is_google_user', 'has_google_connected')
    
    def get_has_google_connected(self, obj):
        """Check if user has Google account connected (has access token)"""
        return bool(obj.google_access_token)


class LoginSerializer(serializers.Serializer):
    """Serializer for email/password login"""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = authenticate(username=email, password=password)
            if not user:
                raise serializers.ValidationError('Invalid email or password.')
            if not user.is_active:
                raise serializers.ValidationError('User account is disabled.')
            attrs['user'] = user
        else:
            raise serializers.ValidationError('Must include "email" and "password".')

        return attrs


class SignupSerializer(serializers.Serializer):
    """Serializer for user registration"""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, style={'input_type': 'password'}, min_length=8)
    username = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    first_name = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    last_name = serializers.CharField(required=False, allow_blank=True, allow_null=True)

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError('A user with this email already exists.')
        return value

    def create(self, validated_data):
        email = validated_data['email']
        password = validated_data['password']
        
        # Get username - use provided or generate from email
        username_value = validated_data.get('username')
        if username_value and username_value.strip():
            base_username = username_value.strip()
        else:
            base_username = email.split('@')[0]
        
        # Get optional fields, handling None and empty strings
        first_name = validated_data.get('first_name') or ''
        last_name = validated_data.get('last_name') or ''
        
        # Ensure username is unique
        username = base_username
        counter = 1
        while User.objects.filter(username=username).exists():
            username = f"{base_username}{counter}"
            counter += 1
        
        try:
            user = User.objects.create_user(
                email=email,
                username=username,
                password=password,
                first_name=first_name.strip() if first_name else '',
                last_name=last_name.strip() if last_name else '',
            )
            return user
        except Exception as e:
            raise serializers.ValidationError(f'Failed to create user: {str(e)}')


class GoogleAuthSerializer(serializers.Serializer):
    """Serializer for Google OAuth credential verification"""
    credential = serializers.CharField()
