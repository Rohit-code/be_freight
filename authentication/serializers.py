from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import User


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model"""
    
    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'first_name', 'last_name', 'picture', 'is_google_user')
        read_only_fields = ('id', 'is_google_user')


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


class GoogleAuthSerializer(serializers.Serializer):
    """Serializer for Google OAuth credential verification"""
    credential = serializers.CharField()
