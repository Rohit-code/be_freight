from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Admin configuration for custom User model"""
    list_display = ('email', 'username', 'first_name', 'last_name', 'is_google_user', 'is_staff', 'is_active', 'created_at')
    list_filter = ('is_google_user', 'is_staff', 'is_active', 'created_at')
    search_fields = ('email', 'username', 'first_name', 'last_name')
    ordering = ('-created_at',)
    
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Additional Info', {
            'fields': ('picture', 'google_id', 'is_google_user')
        }),
    )
    
    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        ('Additional Info', {
            'fields': ('email', 'picture', 'google_id', 'is_google_user')
        }),
    )
