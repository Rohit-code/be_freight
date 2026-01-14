from django.urls import path
from . import views

app_name = 'authentication'

urlpatterns = [
    # Authentication endpoints
    path('login', views.login_view, name='login'),
    path('signup', views.signup_view, name='signup'),
    path('google', views.google_oauth_initiate_view, name='google_oauth_initiate'),
    path('google/callback', views.google_oauth_callback_view, name='google_oauth_callback'),
    path('google/verify', views.google_verify_view, name='google_verify'),  # Keep for backward compatibility
    path('me', views.current_user_view, name='current_user'),
    path('logout', views.logout_view, name='logout'),
    
    # Gmail API endpoints
    path('gmail/list', views.gmail_list_view, name='gmail_list'),
    path('gmail/detail', views.gmail_detail_view, name='gmail_detail'),
    path('gmail/attachment', views.gmail_attachment_view, name='gmail_attachment'),
    path('gmail/send', views.gmail_send_view, name='gmail_send'),
    
    # Google Drive API endpoints
    path('drive/list', views.drive_list_view, name='drive_list'),
    
    # Google Sheets API endpoints
    path('sheets/list', views.sheets_list_view, name='sheets_list'),
    path('sheets/read', views.sheets_read_view, name='sheets_read'),
    
    # Google Docs API endpoints
    path('docs/list', views.docs_list_view, name='docs_list'),
    path('docs/read', views.docs_read_view, name='docs_read'),
    
    # AI API endpoints
    path('ai/status', views.ai_status_view, name='ai_status'),
    path('ai/chat', views.ai_chat_view, name='ai_chat'),
    path('ai/analyze-email', views.ai_analyze_email_view, name='ai_analyze_email'),
    path('ai/generate-email-response', views.ai_generate_email_response_view, name='ai_generate_email_response'),
    path('ai/analyze-spreadsheet', views.ai_analyze_spreadsheet_view, name='ai_analyze_spreadsheet'),
    path('ai/analyze-document', views.ai_analyze_document_view, name='ai_analyze_document'),
]
