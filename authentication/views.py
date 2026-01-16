import secrets
from rest_framework import status, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.shortcuts import redirect
from django.http import HttpResponseRedirect
from decouple import config
from .serializers import UserSerializer, LoginSerializer, SignupSerializer, GoogleAuthSerializer
from .utils import (
    generate_jwt_token, 
    verify_google_token, 
    get_google_oauth_flow, 
    exchange_code_for_token,
    get_gmail_service,
    get_drive_service,
    get_sheets_service,
    get_docs_service,
)

User = get_user_model()


@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    """Email/Password login endpoint"""
    serializer = LoginSerializer(data=request.data)
    
    if serializer.is_valid():
        user = serializer.validated_data['user']
        token = generate_jwt_token(user)
        return Response({
            'user': UserSerializer(user).data,
            'token': token,
        }, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def signup_view(request):
    """User registration endpoint"""
    serializer = SignupSerializer(data=request.data)
    
    if serializer.is_valid():
        try:
            user = serializer.save()
            token = generate_jwt_token(user)
            return Response({
                'user': UserSerializer(user).data,
                'token': token,
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            print(f"[ERROR] signup_view: Error creating user: {str(e)}")
            import traceback
            traceback.print_exc()
            return Response(
                {'error': f'Failed to create user: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    print(f"[ERROR] signup_view: Validation errors: {serializer.errors}")
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([AllowAny])
def google_oauth_initiate_view(request):
    """Initiate Google OAuth flow - redirects to Google"""
    try:
        flow = get_google_oauth_flow(request)
        
        # Generate state for CSRF protection
        state = secrets.token_urlsafe(32)
        
        # Ensure session is created
        if not request.session.session_key:
            request.session.create()
        
        # Save state in session
        request.session['oauth_state'] = state
        request.session.modified = True
        request.session.save()
        
        # Get authorization URL
        authorization_url, returned_state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='false',
            state=state,
            prompt='consent'
        )
        
        return redirect(authorization_url)
        
    except Exception as e:
        print(f"[ERROR] google_oauth_initiate_view: {str(e)}")
        import traceback
        traceback.print_exc()
        frontend_url = config('GOOGLE_FRONTEND_CALLBACK_URL', default='http://localhost:3000/api/auth/google/callback')
        error_message = str(e).replace(' ', '_').replace('=', '_')[:50]
        return redirect(f"{frontend_url}?error=oauth_init_failed&details={error_message}")


@api_view(['GET'])
@permission_classes([AllowAny])
def google_oauth_callback_view(request):
    """Handle Google OAuth callback - receives code and exchanges for token"""
    code = request.GET.get('code')
    state = request.GET.get('state')
    error = request.GET.get('error')
    
    frontend_url = config('GOOGLE_FRONTEND_CALLBACK_URL', default='http://localhost:3000/api/auth/google/callback')
    
    if error:
        error_description = request.GET.get('error_description', '')
        from urllib.parse import quote
        error_desc_encoded = quote(error_description) if error_description else ''
        return redirect(f"{frontend_url}?error={error}&details={error_desc_encoded}")
    
    if not code:
        return redirect(f"{frontend_url}?error=no_code")
    
    # Verify state (CSRF protection)
    session_state = request.session.get('oauth_state')
    if state != session_state:
        print(f"[ERROR] google_oauth_callback_view: State mismatch")
        return redirect(f"{frontend_url}?error=state_mismatch")
    
    try:
        google_user_info = exchange_code_for_token(code)
        
        # Get or create user
        user, created = User.objects.get_or_create(
            email=google_user_info['email'],
            defaults={
                'username': google_user_info['email'].split('@')[0],
                'first_name': google_user_info['name'].split()[0] if google_user_info['name'] else '',
                'last_name': ' '.join(google_user_info['name'].split()[1:]) if len(google_user_info['name'].split()) > 1 else '',
                'picture': google_user_info.get('picture', ''),
                'google_id': google_user_info['google_id'],
                'is_google_user': True,
                'google_access_token': google_user_info.get('access_token', ''),
                'google_refresh_token': google_user_info.get('refresh_token', ''),
                'google_token_expiry': google_user_info.get('token_expiry'),
            }
        )
        
        # Update user if not newly created (always update tokens)
        if not created:
            if not user.google_id:
                user.google_id = google_user_info['google_id']
                user.is_google_user = True
            if google_user_info.get('picture') and not user.picture:
                user.picture = google_user_info['picture']
            if google_user_info.get('access_token'):
                user.google_access_token = google_user_info['access_token']
            if google_user_info.get('refresh_token'):
                user.google_refresh_token = google_user_info['refresh_token']
            if google_user_info.get('token_expiry'):
                user.google_token_expiry = google_user_info['token_expiry']
            user.save()
        
        token = generate_jwt_token(user)
        
        # Clear session state
        if 'oauth_state' in request.session:
            del request.session['oauth_state']
        
        return redirect(f"{frontend_url}?token={token}&success=true")
        
    except Exception as e:
        print(f"[ERROR] google_oauth_callback_view: {str(e)}")
        import traceback
        traceback.print_exc()
        return redirect(f"{frontend_url}?error=auth_failed")


@api_view(['POST'])
@permission_classes([AllowAny])
def google_verify_view(request):
    """Google OAuth credential verification endpoint"""
    print(f"[google_verify_view] Google OAuth verification attempt received")
    serializer = GoogleAuthSerializer(data=request.data)
    
    if not serializer.is_valid():
        print(f"[google_verify_view] Invalid serializer: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    credential = serializer.validated_data['credential']
    print(f"[google_verify_view] Credential received, length: {len(credential)}")
    
    try:
        # Verify Google token
        print(f"[google_verify_view] Verifying Google token...")
        google_user_info = verify_google_token(credential)
        print(f"[google_verify_view] Google token verified: email={google_user_info.get('email')}")
        
        # Get or create user
        user, created = User.objects.get_or_create(
            email=google_user_info['email'],
            defaults={
                'username': google_user_info['email'].split('@')[0],
                'first_name': google_user_info['name'].split()[0] if google_user_info['name'] else '',
                'last_name': ' '.join(google_user_info['name'].split()[1:]) if len(google_user_info['name'].split()) > 1 else '',
                'picture': google_user_info.get('picture', ''),
                'google_id': google_user_info['google_id'],
                'is_google_user': True,
            }
        )
        print(f"[google_verify_view] User {'created' if created else 'found'}: user_id={user.id}, email={user.email}")
        
        # Update user if not newly created
        if not created:
            if not user.google_id:
                user.google_id = google_user_info['google_id']
                user.is_google_user = True
            if google_user_info.get('picture') and not user.picture:
                user.picture = google_user_info['picture']
            user.save()
            print(f"[google_verify_view] User updated")
        
        # Generate JWT token
        token = generate_jwt_token(user)
        print(f"[google_verify_view] JWT token generated, length: {len(token)}")
        
        return Response({
            'user': UserSerializer(user).data,
            'token': token,
        }, status=status.HTTP_200_OK)
        
    except ValueError as e:
        print(f"[google_verify_view] ValueError: {str(e)}")
        return Response(
            {'error': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        print(f"[google_verify_view] Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        return Response(
            {'error': 'Authentication failed. Please try again.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def current_user_view(request):
    """Get current authenticated user"""
    if not request.user or not request.user.is_authenticated:
        return Response(
            {'error': 'User not authenticated'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    token = auth_header.replace('Bearer ', '') if auth_header.startswith('Bearer ') else ''
    
    return Response({
        'user': UserSerializer(request.user).data,
        'token': token,
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """Logout endpoint (client should discard token)"""
    return Response(
        {'message': 'Successfully logged out'},
        status=status.HTTP_200_OK
    )


# ========== GMAIL API ENDPOINTS ==========

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def gmail_list_view(request):
    """Get list of Gmail messages with pagination"""
    try:
        user = request.user
        if not user.google_access_token:
            return Response(
                {'error': 'Google OAuth tokens not found. Please log in with Google.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        max_results = int(request.GET.get('max_results', 20))
        page_token = request.GET.get('page_token')
        
        service = get_gmail_service(user)
        
        # Build list request with optional page token
        list_params = {
            'userId': 'me',
            'maxResults': max_results
        }
        
        if page_token:
            list_params['pageToken'] = page_token
        
        results = service.users().messages().list(**list_params).execute()
        
        messages = results.get('messages', [])
        next_page_token = results.get('nextPageToken')
        
        # Get full message details
        message_list = []
        for msg in messages:
            message = service.users().messages().get(
                userId='me',
                id=msg['id'],
                format='metadata',
                metadataHeaders=['From', 'To', 'Cc', 'Bcc', 'Subject', 'Date']
            ).execute()
            
            headers = {h['name']: h['value'] for h in message['payload'].get('headers', [])}
            
            # Check for attachments
            has_attachments = False
            attachment_count = 0
            payload = message.get('payload', {})
            
            def count_attachments(part):
                """Recursively count attachments in message parts"""
                count = 0
                if part.get('filename') and part.get('body', {}).get('attachmentId'):
                    count += 1
                if 'parts' in part:
                    for subpart in part['parts']:
                        count += count_attachments(subpart)
                return count
            
            attachment_count = count_attachments(payload)
            has_attachments = attachment_count > 0
            
            message_list.append({
                'id': message['id'],
                'threadId': message['threadId'],
                'snippet': message.get('snippet', ''),
                'from': headers.get('From', ''),
                'to': headers.get('To', ''),
                'cc': headers.get('Cc', ''),
                'bcc': headers.get('Bcc', ''),
                'subject': headers.get('Subject', ''),
                'date': headers.get('Date', ''),
                'hasAttachments': has_attachments,
                'attachmentCount': attachment_count,
            })
        
        return Response({
            'messages': message_list,
            'total': len(message_list),
            'nextPageToken': next_page_token,
            'hasMore': bool(next_page_token)
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        print(f"[ERROR] gmail_list_view: {str(e)}")
        import traceback
        traceback.print_exc()
        return Response(
            {'error': f'Failed to fetch emails: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def gmail_detail_view(request):
    """Get full details of a specific Gmail message including body and attachments"""
    try:
        user = request.user
        if not user.google_access_token:
            return Response(
                {'error': 'Google OAuth tokens not found. Please log in with Google.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        message_id = request.GET.get('message_id')
        if not message_id:
            return Response(
                {'error': 'Missing required parameter: message_id'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        service = get_gmail_service(user)
        
        # Get full message with body
        message = service.users().messages().get(
            userId='me',
            id=message_id,
            format='full',
            metadataHeaders=['From', 'To', 'Cc', 'Bcc', 'Subject', 'Date', 'Delivered-To']
        ).execute()
        
        payload = message.get('payload', {})
        
        # Extract headers - check main payload first, then nested parts
        def extract_headers(part, collected_headers=None):
            """Recursively extract headers from message parts"""
            if collected_headers is None:
                collected_headers = {}
            
            if 'headers' in part:
                for header in part['headers']:
                    header_name = header['name']
                    header_value = header['value']
                    # Only add if not already present (prefer first occurrence from main payload)
                    if header_name not in collected_headers:
                        collected_headers[header_name] = header_value
                    # For "To" header, always prefer the first non-empty value
                    elif header_name == 'To' and not collected_headers.get('To'):
                        collected_headers[header_name] = header_value
            
            # Also check nested parts
            if 'parts' in part:
                for subpart in part['parts']:
                    extract_headers(subpart, collected_headers)
            
            return collected_headers
        
        headers = extract_headers(payload)
        
        # Also check if headers are at the top level of the message (sometimes Gmail stores them there)
        if 'headers' in message:
            for header in message.get('headers', []):
                header_name = header.get('name', '')
                header_value = header.get('value', '')
                if header_name and header_name not in headers:
                    headers[header_name] = header_value
                elif header_name == 'To' and not headers.get('To'):
                    headers[header_name] = header_value
        
        # Check if this is a sent message (check labelIds)
        label_ids = message.get('labelIds', [])
        is_sent = 'SENT' in label_ids
        
        # For sent messages, the "To" header should always be present
        # If missing, it might be in an envelope or we need to check the message structure
        to_header = headers.get('To', '')
        
        # For sent messages, if "To" is missing, try to get it from the message payload
        # Sometimes Gmail stores it differently for sent messages
        if not to_header and is_sent:
            # Check if there's a "Delivered-To" or envelope information
            to_header = headers.get('Delivered-To', '') or headers.get('Envelope-To', '')
            
            # Also check the message payload structure - sometimes "To" is in a different part
            # For sent messages, Gmail might store recipient info differently
            if not to_header:
                # Try to extract from the raw message if available
                # Check all header variations
                for header_name in ['To', 'X-Original-To', 'Delivered-To', 'Envelope-To']:
                    if headers.get(header_name):
                        to_header = headers.get(header_name)
                        break
        
        # Extract email body (prefer HTML over plain text)
        html_body = ''
        plain_body = ''
        
        def extract_body(part):
            """Recursively extract body text from message parts"""
            nonlocal html_body, plain_body
            
            if part.get('mimeType') == 'text/plain':
                data = part.get('body', {}).get('data', '')
                if data:
                    import base64
                    text = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                    if text and not plain_body:
                        plain_body = text
            elif part.get('mimeType') == 'text/html':
                data = part.get('body', {}).get('data', '')
                if data:
                    import base64
                    html = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                    if html and not html_body:
                        html_body = html
            
            if 'parts' in part:
                for subpart in part['parts']:
                    extract_body(subpart)
        
        extract_body(payload)
        
        # Prefer HTML over plain text
        body = html_body if html_body else plain_body
        
        # Extract attachments
        attachments = []
        def extract_attachments(part, path=''):
            """Recursively extract attachment information"""
            if part.get('filename') and part.get('body', {}).get('attachmentId'):
                attachments.append({
                    'filename': part.get('filename', ''),
                    'mimeType': part.get('mimeType', ''),
                    'size': part.get('body', {}).get('size', 0),
                    'attachmentId': part.get('body', {}).get('attachmentId', ''),
                })
            
            if 'parts' in part:
                for i, subpart in enumerate(part['parts']):
                    extract_attachments(subpart, f"{path}.{i}")
        
        extract_attachments(payload)
        
        return Response({
            'id': message['id'],
            'threadId': message['threadId'],
            'snippet': message.get('snippet', ''),
            'from': headers.get('From', ''),
            'to': to_header,
            'cc': headers.get('Cc', ''),
            'bcc': headers.get('Bcc', ''),
            'subject': headers.get('Subject', ''),
            'date': headers.get('Date', ''),
            'body': body,
            'attachments': attachments,
            'attachmentCount': len(attachments),
            'isSent': is_sent,
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        print(f"[ERROR] gmail_detail_view: {str(e)}")
        import traceback
        traceback.print_exc()
        return Response(
            {'error': f'Failed to fetch email details: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def gmail_attachment_view(request):
    """Download a Gmail attachment"""
    try:
        user = request.user
        if not user.google_access_token:
            from django.http import HttpResponse
            return HttpResponse(
                'Google OAuth tokens not found',
                status=400,
                content_type='text/plain'
            )
        
        message_id = request.GET.get('message_id')
        attachment_id = request.GET.get('attachment_id')
        filename = request.GET.get('filename', 'attachment')
        
        if not message_id or not attachment_id:
            from django.http import HttpResponse
            return HttpResponse(
                'Missing required parameters',
                status=400,
                content_type='text/plain'
            )
        
        service = get_gmail_service(user)
        
        attachment = service.users().messages().attachments().get(
            userId='me',
            messageId=message_id,
            id=attachment_id
        ).execute()
        
        import base64
        file_data = base64.urlsafe_b64decode(attachment['data'])
        
        from django.http import HttpResponse
        response = HttpResponse(file_data, content_type=attachment.get('mimeType', 'application/octet-stream'))
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
        
    except Exception as e:
        print(f"[ERROR] gmail_attachment_view: {str(e)}")
        import traceback
        traceback.print_exc()
        from django.http import HttpResponse
        return HttpResponse(
            f'Failed to download attachment: {str(e)}',
            status=500,
            content_type='text/plain'
        )


def get_user_signature(user):
    """Extract user's email signature from a recent sent message, including embedded images"""
    try:
        print(f"[DEBUG] get_user_signature: Starting signature extraction for user {user.email}")
        service = get_gmail_service(user)
        
        # Get recent sent messages - try to find ones with HTML content
        # Check more messages to find one that was sent from Gmail (not our platform)
        results = service.users().messages().list(
            userId='me',
            q='in:sent',
            maxResults=10  # Check more messages to find one with HTML/signature
        ).execute()
        
        messages = results.get('messages', [])
        print(f"[DEBUG] get_user_signature: Found {len(messages)} recent sent messages")
        
        if not messages:
            print(f"[DEBUG] get_user_signature: No sent messages found")
            return None, None  # Return signature and embedded images
        
        # Try each recent message to find one with a signature
        for idx, msg in enumerate(messages):
            try:
                print(f"[DEBUG] get_user_signature: Checking message {idx + 1}/{len(messages)}, ID: {msg['id']}")
                sent_message = service.users().messages().get(
                    userId='me',
                    id=msg['id'],
                    format='full'
                ).execute()
                
                payload = sent_message.get('payload', {})
                message_id = msg['id']
                
                # Extract HTML body and embedded images
                def extract_html_and_images(part, collected_html=None, embedded_images=None, all_parts=None):
                    """Recursively extract HTML body and embedded images from message parts"""
                    if collected_html is None:
                        collected_html = []
                    if embedded_images is None:
                        embedded_images = {}
                    if all_parts is None:
                        all_parts = []
                    
                    mime_type = part.get('mimeType', '')
                    print(f"[DEBUG] get_user_signature: Checking part with mimeType: {mime_type}")
                    
                    # Store all parts for later image matching (including nested parts)
                    all_parts.append(part)
                    
                    # IMPORTANT: For multipart types, we MUST recursively check nested parts FIRST
                    # Gmail structures emails as: multipart/alternative -> multipart/related -> images
                    # Images are often in multipart/related sections nested inside multipart/alternative
                    if mime_type.startswith('multipart/'):
                        print(f"[DEBUG] get_user_signature: Found multipart type: {mime_type}, checking {len(part.get('parts', []))} nested parts")
                        if 'parts' in part:
                            for idx, subpart in enumerate(part['parts']):
                                print(f"[DEBUG] get_user_signature:   Nested part {idx}: {subpart.get('mimeType', 'N/A')}")
                                extract_html_and_images(subpart, collected_html, embedded_images, all_parts)
                        # Don't process this part further - already handled nested parts
                        return collected_html, embedded_images, all_parts
                    
                    # Check for embedded images (Content-ID attachments)
                    content_id = None
                    headers = part.get('headers', [])
                    for header in headers:
                        header_name = header.get('name', '').lower()
                        if header_name == 'content-id':
                            content_id = header.get('value', '').strip('<>')
                            print(f"[DEBUG] get_user_signature: Found Content-ID header: {content_id}")
                        elif header_name == 'content-disposition':
                            print(f"[DEBUG] get_user_signature: Content-Disposition: {header.get('value', '')}")
                    
                    if mime_type == 'text/html':
                        data = part.get('body', {}).get('data', '')
                        if data:
                            import base64
                            html_body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                            collected_html.append(html_body)
                            print(f"[DEBUG] get_user_signature: Found HTML part, length: {len(html_body)} chars")
                    
                    # Extract embedded images (usually image/* mime types)
                    # Check for images even without Content-ID initially - we'll match them later
                    if mime_type.startswith('image/'):
                        print(f"[DEBUG] get_user_signature: Found image part: {mime_type}")
                        print(f"[DEBUG] get_user_signature: Image part headers: {[h.get('name') + ': ' + h.get('value') for h in headers]}")
                        attachment_id = part.get('body', {}).get('attachmentId')
                        filename = part.get('filename', '')
                        print(f"[DEBUG] get_user_signature: Image filename: {filename}, attachmentId: {attachment_id}")
                        
                        if attachment_id:
                            try:
                                # Download the embedded image
                                attachment = service.users().messages().attachments().get(
                                    userId='me',
                                    messageId=message_id,
                                    id=attachment_id
                                ).execute()
                                
                                import base64
                                image_data = base64.urlsafe_b64decode(attachment['data'])
                                
                                # Use Content-ID if available, otherwise use filename or generate one
                                if content_id:
                                    img_cid = content_id
                                elif filename:
                                    # Use filename as key (might match cid in HTML)
                                    img_cid = filename
                                else:
                                    img_cid = f'image_{len(embedded_images)}'
                                
                                embedded_images[img_cid] = {
                                    'data': image_data,
                                    'mime_type': mime_type,
                                    'filename': filename or f'image.{mime_type.split("/")[1]}',
                                    'content_id': content_id  # Store original Content-ID if any
                                }
                                print(f"[DEBUG] get_user_signature: Extracted embedded image: {img_cid}, size: {len(image_data)} bytes")
                            except Exception as e:
                                print(f"[DEBUG] get_user_signature: Failed to extract embedded image: {str(e)}")
                                import traceback
                                traceback.print_exc()
                    
                    # Only process nested parts if not already processed above (for multipart types)
                    if not mime_type.startswith('multipart/') and 'parts' in part:
                        for subpart in part['parts']:
                            extract_html_and_images(subpart, collected_html, embedded_images, all_parts)
                    
                    return collected_html, embedded_images, all_parts
                
                html_parts, embedded_images, all_parts = extract_html_and_images(payload)
                html_content = ''.join(html_parts) if html_parts else ''
                
                # Check HTML for cid: references and match them with extracted images
                if html_content:
                    import re
                    # Find all cid: references in HTML (various formats)
                    cid_patterns = [
                        r'cid:([^"\'<>\s]+)',  # cid:xxxxx
                        r'Content-ID:\s*<([^>]+)>',  # Content-ID: <xxxxx>
                    ]
                    cid_matches = []
                    for pattern in cid_patterns:
                        matches = re.findall(pattern, html_content, re.IGNORECASE)
                        cid_matches.extend(matches)
                    
                    print(f"[DEBUG] get_user_signature: Found {len(cid_matches)} cid: references in HTML: {cid_matches}")
                    
                    # Also look for img tags to see how images are referenced
                    img_tags = re.findall(r'<img[^>]+>', html_content, re.IGNORECASE)
                    print(f"[DEBUG] get_user_signature: Found {len(img_tags)} img tags in HTML")
                    for img_tag in img_tags:
                        print(f"[DEBUG] get_user_signature: Image tag: {img_tag[:200]}")
                    
                    # If we have images but no cid matches, try to match by filename
                    if embedded_images and not cid_matches:
                        # Look for img src attributes that might reference images
                        img_srcs = re.findall(r'<img[^>]+src=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
                        print(f"[DEBUG] get_user_signature: Found {len(img_srcs)} img src attributes: {img_srcs}")
                        
                        # Check if any match our extracted images
                        for img_src in img_srcs:
                            for img_key in list(embedded_images.keys()):
                                if img_key in img_src or img_src in img_key:
                                    print(f"[DEBUG] get_user_signature: Matched image {img_key} with src {img_src}")
                                    # Update the key to match the cid reference if needed
                                    if 'cid:' in img_src:
                                        cid_ref = img_src.split('cid:')[-1].strip('<>')
                                        if cid_ref != img_key:
                                            embedded_images[cid_ref] = embedded_images.pop(img_key)
                                            print(f"[DEBUG] get_user_signature: Updated image key to match cid: {cid_ref}")
                    
                    # If we still don't have images but found cid references, try to extract them
                    if not embedded_images and cid_matches:
                        print(f"[DEBUG] get_user_signature: No images extracted yet, searching parts for cid references")
                        
                        # Try to find matching parts for each cid
                        for cid_ref in cid_matches:
                            cid_clean = cid_ref.strip('<>')
                            print(f"[DEBUG] get_user_signature: Looking for Content-ID: {cid_clean}")
                            
                            # Search through all parts for matching Content-ID
                            for part_idx, part in enumerate(all_parts):
                                mime_type = part.get('mimeType', '')
                                headers = part.get('headers', [])
                                
                                # Print all headers for debugging
                                if mime_type.startswith('image/'):
                                    print(f"[DEBUG] get_user_signature: Found image part {part_idx}: {mime_type}")
                                    print(f"[DEBUG] get_user_signature: Part headers: {[(h.get('name'), h.get('value')) for h in headers]}")
                                
                                # Check Content-ID header
                                for header in headers:
                                    header_name = header.get('name', '').lower()
                                    header_value = header.get('value', '')
                                    
                                    if header_name == 'content-id':
                                        # Content-ID can be with or without angle brackets
                                        clean_header_value = header_value.strip('<>')
                                        print(f"[DEBUG] get_user_signature: Comparing Content-ID '{clean_header_value}' with '{cid_clean}'")
                                        
                                        if clean_header_value == cid_clean or cid_clean in clean_header_value or clean_header_value in cid_clean:
                                            print(f"[DEBUG] get_user_signature: Found matching part for cid: {cid_clean}")
                                            # Extract the image
                                            attachment_id = part.get('body', {}).get('attachmentId')
                                            if attachment_id:
                                                try:
                                                    attachment = service.users().messages().attachments().get(
                                                        userId='me',
                                                        messageId=message_id,
                                                        id=attachment_id
                                                    ).execute()
                                                    
                                                    import base64
                                                    image_data = base64.urlsafe_b64decode(attachment['data'])
                                                    mime_type = part.get('mimeType', 'image/png')
                                                    
                                                    embedded_images[cid_clean] = {
                                                        'data': image_data,
                                                        'mime_type': mime_type,
                                                        'filename': part.get('filename', f'image.{mime_type.split("/")[1]}')
                                                    }
                                                    print(f"[DEBUG] get_user_signature: Extracted image for cid {cid_clean}, size: {len(image_data)} bytes")
                                                except Exception as e:
                                                    print(f"[DEBUG] get_user_signature: Failed to extract image for cid {cid_clean}: {str(e)}")
                                                    import traceback
                                                    traceback.print_exc()
                                            else:
                                                print(f"[DEBUG] get_user_signature: Part matched but no attachmentId found")
                                            break
                                
                                # Also check if the part itself might be the image (some structures embed images directly)
                                if mime_type.startswith('image/') and not embedded_images.get(cid_clean):
                                    # Check if filename matches or if this might be our image
                                    filename = part.get('filename', '')
                                    if filename and ('image' in filename.lower() or 'png' in filename.lower() or 'jpg' in filename.lower()):
                                        print(f"[DEBUG] get_user_signature: Trying to extract image part {part_idx} by filename: {filename}")
                                        attachment_id = part.get('body', {}).get('attachmentId')
                                        if attachment_id:
                                            try:
                                                attachment = service.users().messages().attachments().get(
                                                    userId='me',
                                                    messageId=message_id,
                                                    id=attachment_id
                                                ).execute()
                                                
                                                import base64
                                                image_data = base64.urlsafe_b64decode(attachment['data'])
                                                
                                                # Use the cid from HTML as the key
                                                embedded_images[cid_clean] = {
                                                    'data': image_data,
                                                    'mime_type': mime_type,
                                                    'filename': filename
                                                }
                                                print(f"[DEBUG] get_user_signature: Extracted image by filename for cid {cid_clean}, size: {len(image_data)} bytes")
                                            except Exception as e:
                                                print(f"[DEBUG] get_user_signature: Failed to extract image by filename: {str(e)}")
                                
                                if embedded_images.get(cid_clean):
                                    break  # Found this one, move to next cid
                            
                            if not embedded_images.get(cid_clean):
                                print(f"[DEBUG] get_user_signature: WARNING: Could not find image for cid: {cid_clean}")
                                print(f"[DEBUG] get_user_signature: Total parts checked: {len(all_parts)}")
                                # Print summary of all parts
                                for i, p in enumerate(all_parts):
                                    print(f"[DEBUG] get_user_signature: Part {i}: mimeType={p.get('mimeType', 'N/A')}, filename={p.get('filename', 'N/A')}")
                                    p_headers = p.get('headers', [])
                                    for h in p_headers:
                                        if h.get('name', '').lower() == 'content-id':
                                            print(f"[DEBUG] get_user_signature:   Content-ID: {h.get('value', 'N/A')}")
                
                if not html_content:
                    print(f"[DEBUG] get_user_signature: Message {idx + 1} has no HTML content, skipping")
                    # Also check the payload structure for debugging
                    print(f"[DEBUG] get_user_signature: Payload mimeType: {payload.get('mimeType', 'N/A')}")
                    print(f"[DEBUG] get_user_signature: Payload has parts: {bool(payload.get('parts'))}")
                    if payload.get('parts'):
                        print(f"[DEBUG] get_user_signature: Number of parts: {len(payload.get('parts', []))}")
                        for i, part in enumerate(payload.get('parts', [])):
                            print(f"[DEBUG] get_user_signature: Part {i} mimeType: {part.get('mimeType', 'N/A')}")
                    continue
                
                print(f"[DEBUG] get_user_signature: Message {idx + 1} has HTML content! Length: {len(html_content)} chars")
                
                print(f"[DEBUG] get_user_signature: Message {idx + 1} HTML content length: {len(html_content)} chars")
                print(f"[DEBUG] get_user_signature: HTML preview (first 200 chars): {html_content[:200]}")
                
                import re
                
                # First, try to extract Gmail signature div (most reliable method)
                # Gmail wraps signatures in <div class="gmail_signature">
                # Find the start of gmail_signature div
                sig_start_match = re.search(r'<div[^>]*class=["\']gmail_signature["\'][^>]*>', html_content, re.IGNORECASE)
                if sig_start_match:
                    start_pos = sig_start_match.start()
                    sig_start_tag = sig_start_match.group(0)
                    print(f"[DEBUG] get_user_signature: Found gmail_signature div start at position {start_pos}")
                    
                    # Extract everything from the start of gmail_signature div to the end
                    # We need to find the matching closing divs
                    remaining_html = html_content[start_pos:]
                    
                    # Count div tags to find the end
                    # Start with the opening gmail_signature div
                    div_count = 1
                    pos = len(sig_start_tag)
                    signature_html = sig_start_tag
                    
                    while pos < len(remaining_html) and div_count > 0:
                        # Look for opening or closing div tags
                        next_open = remaining_html.find('<div', pos)
                        next_close = remaining_html.find('</div>', pos)
                        
                        if next_close == -1:
                            # No more closing tags, take everything
                            signature_html += remaining_html[pos:]
                            break
                        
                        if next_open != -1 and next_open < next_close:
                            # Found an opening div first
                            signature_html += remaining_html[pos:next_open + 4]
                            div_count += 1
                            pos = next_open + 4
                        else:
                            # Found a closing div
                            signature_html += remaining_html[pos:next_close + 6]
                            div_count -= 1
                            pos = next_close + 6
                            
                            # If we've closed all divs, we're done
                            if div_count == 0:
                                break
                    
                    signature = signature_html.strip()
                    print(f"[DEBUG] get_user_signature: Extracted gmail_signature div, length: {len(signature)} chars")
                    print(f"[DEBUG] get_user_signature: Signature preview: {signature[:300]}")
                    
                    if signature and len(signature) > 20:
                        print(f"[DEBUG] get_user_signature: Successfully extracted signature from gmail_signature div")
                        print(f"[DEBUG] get_user_signature: Found {len(embedded_images)} embedded images")
                        return signature, embedded_images
                
                # Try to extract signature - typically after a delimiter like "-- "
                # Split by common signature delimiters
                # Gmail signatures usually come after "--" or "<br>--<br>"
                signature_delimiters = [
                    r'<br[^>]*>\s*--\s*<br[^>]*>',
                    r'<div[^>]*>--\s*</div>',
                    r'<p[^>]*>--\s*</p>',
                    r'\n--\s*\n',
                    r'<br[^>]*>--<br[^>]*>',
                ]
                
                for delimiter_idx, delimiter in enumerate(signature_delimiters):
                    parts = re.split(delimiter, html_content, flags=re.IGNORECASE | re.DOTALL)
                    if len(parts) > 1:
                        print(f"[DEBUG] get_user_signature: Found signature delimiter {delimiter_idx + 1}, split into {len(parts)} parts")
                        # Signature is everything after the delimiter
                        signature = parts[-1].strip()
                        print(f"[DEBUG] get_user_signature: Extracted signature length: {len(signature)} chars")
                        print(f"[DEBUG] get_user_signature: Signature preview: {signature[:200]}")
                        
                        if signature and len(signature) > 10:  # Make sure it's substantial
                            # Clean up the signature
                            signature = re.sub(r'^\s*<br[^>]*>', '', signature, flags=re.IGNORECASE)
                            signature = signature.strip()
                            if signature:
                                print(f"[DEBUG] get_user_signature: Successfully extracted signature (final length: {len(signature)} chars)")
                                print(f"[DEBUG] get_user_signature: Found {len(embedded_images)} embedded images")
                                return signature, embedded_images
                
                # If no delimiter found, try to get the last part (might be signature)
                # Look for common signature patterns (name, company, website, images)
                if 'gamyam' in html_content.lower() or 'www.' in html_content.lower() or 'gmail_signature' in html_content.lower():
                    print(f"[DEBUG] get_user_signature: Found signature keywords, trying alternative extraction")
                    # Try to extract the gmail_signature div content
                    sig_match = re.search(r'<div[^>]*class=["\']gmail_signature["\'][^>]*>(.*)', html_content, re.DOTALL | re.IGNORECASE)
                    if sig_match:
                        # Extract from gmail_signature to end
                        remaining = sig_match.group(0)
                        # Find the closing tags
                        # Count opening and closing divs to find the end
                        div_count = remaining.count('<div') - remaining.count('</div>')
                        # Try to find where the gmail_signature div ends
                        potential_sig = remaining
                        print(f"[DEBUG] get_user_signature: Alternative extraction found {len(potential_sig)} chars")
                        if potential_sig and len(potential_sig) > 20:
                            print(f"[DEBUG] get_user_signature: Using alternative signature extraction")
                            print(f"[DEBUG] get_user_signature: Found {len(embedded_images)} embedded images")
                            return potential_sig, embedded_images
                    
                    # Fallback: Split by common patterns and take the last meaningful part
                    parts = re.split(r'(<br[^>]*>){3,}', html_content, flags=re.IGNORECASE)
                    if len(parts) > 1:
                        potential_sig = parts[-1].strip()
                        print(f"[DEBUG] get_user_signature: Alternative extraction found {len(potential_sig)} chars")
                        if potential_sig and len(potential_sig) > 20:
                            print(f"[DEBUG] get_user_signature: Using alternative signature extraction")
                            print(f"[DEBUG] get_user_signature: Found {len(embedded_images)} embedded images")
                            return potential_sig, embedded_images
                else:
                    print(f"[DEBUG] get_user_signature: No signature keywords found in message {idx + 1}")
                            
            except Exception as e:
                print(f"[DEBUG] get_user_signature: Error processing message {idx + 1}: {str(e)}")
                import traceback
                traceback.print_exc()
                continue
        
        print(f"[DEBUG] get_user_signature: No signature found in any recent messages")
        return None, None
        
    except Exception as e:
        print(f"[ERROR] get_user_signature: {str(e)}")
        import traceback
        traceback.print_exc()
        return None, None


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def gmail_send_view(request):
    """Send an email via Gmail with signature support"""
    try:
        user = request.user
        if not user.google_access_token:
            return Response(
                {'error': 'Google OAuth tokens not found. Please log in with Google.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        to = request.data.get('to')
        subject = request.data.get('subject')
        body = request.data.get('body')
        include_signature = request.data.get('include_signature', True)  # Default to True
        
        if not to or not subject or not body:
            return Response(
                {'error': 'Missing required fields: to, subject, body'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        import base64
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from email.mime.image import MIMEImage
        
        # Try to get user's signature from Gmail (including embedded images)
        signature_html = None
        embedded_images = None
        if include_signature:
            print(f"[DEBUG] gmail_send_view: Attempting to get user signature")
            signature_html, embedded_images = get_user_signature(user)
            if signature_html:
                print(f"[DEBUG] gmail_send_view: Signature found and will be included (length: {len(signature_html)} chars)")
                if embedded_images:
                    print(f"[DEBUG] gmail_send_view: Found {len(embedded_images)} embedded images to include")
            else:
                print(f"[DEBUG] gmail_send_view: No signature found, email will be sent without signature")
        else:
            print(f"[DEBUG] gmail_send_view: Signature inclusion disabled by user")
        
        # Determine if body is HTML or plain text
        is_html = '<' in body and '>' in body and ('<br' in body or '<div' in body or '<p' in body)
        print(f"[DEBUG] gmail_send_view: Body is HTML: {is_html}, Body length: {len(body)} chars")
        
        if is_html or signature_html:
            # Use multipart/related for HTML with embedded images, or multipart/alternative
            if embedded_images:
                msg = MIMEMultipart('related')  # Use 'related' to support embedded images
            else:
                msg = MIMEMultipart('alternative')
            
            # Create alternative part for text/html and text/plain
            alt_part = MIMEMultipart('alternative')
            
            # Plain text version
            plain_body = body
            if signature_html:
                # Convert HTML signature to plain text
                import re
                plain_signature = re.sub(r'<[^>]+>', '', signature_html)
                plain_signature = plain_signature.replace('&nbsp;', ' ')
                plain_signature = re.sub(r'\s+', ' ', plain_signature).strip()
                plain_body += '\n\n--\n' + plain_signature
            
            alt_part.attach(MIMEText(plain_body, 'plain'))
            
            # HTML version
            html_body = body
            if signature_html:
                # Append signature to HTML body with proper delimiter
                html_body += '<br><br>--<br>' + signature_html
                print(f"[DEBUG] gmail_send_view: Added signature to HTML body (total length: {len(html_body)} chars)")
            elif not is_html:
                # Convert plain text to HTML if needed
                html_body = html_body.replace('\n', '<br>')
                print(f"[DEBUG] gmail_send_view: Converted plain text to HTML")
            
            alt_part.attach(MIMEText(html_body, 'html'))
            msg.attach(alt_part)
            
            # Attach embedded images with Content-ID headers
            if embedded_images:
                for content_id, image_info in embedded_images.items():
                    img = MIMEImage(image_info['data'], _subtype=image_info['mime_type'].split('/')[1])
                    img.add_header('Content-ID', f'<{content_id}>')
                    img.add_header('Content-Disposition', 'inline', filename=image_info['filename'])
                    msg.attach(img)
                    print(f"[DEBUG] gmail_send_view: Attached embedded image: {content_id}")
            
            print(f"[DEBUG] gmail_send_view: Created multipart message with HTML, plain text, and embedded images")
        else:
            # Plain text message
            msg = MIMEText(body)
            if signature_html:
                # Add plain text signature
                import re
                plain_signature = re.sub(r'<[^>]+>', '', signature_html)
                plain_signature = plain_signature.replace('&nbsp;', ' ')
                plain_signature = re.sub(r'\s+', ' ', plain_signature).strip()
                body += '\n\n--\n' + plain_signature
                msg = MIMEText(body)
        
        msg['To'] = to
        msg['Subject'] = subject
        # Gmail will set 'From' automatically based on authenticated account
        
        # Ensure proper encoding
        raw_message = base64.urlsafe_b64encode(msg.as_bytes()).decode('utf-8')
        
        service = get_gmail_service(user)
        print(f"[DEBUG] gmail_send_view: Sending email to {to} with subject: {subject}")
        result = service.users().messages().send(
            userId='me',
            body={'raw': raw_message}
        ).execute()
        
        message_id = result.get('id')
        print(f"[DEBUG] gmail_send_view: Email sent successfully, message ID: {message_id}")
        
        return Response({
            'message': 'Email sent successfully',
            'messageId': message_id,
            'signature_included': bool(signature_html) if include_signature else False
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        print(f"[ERROR] gmail_send_view: {str(e)}")
        import traceback
        traceback.print_exc()
        return Response(
            {'error': f'Failed to send email: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


# ========== GOOGLE DRIVE API ENDPOINTS ==========

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def drive_list_view(request):
    """List files in Google Drive with pagination"""
    try:
        user = request.user
        if not user.google_access_token:
            return Response(
                {'error': 'Google OAuth tokens not found. Please log in with Google.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        max_results = int(request.GET.get('max_results', 50))
        page_token = request.GET.get('page_token')
        mime_type = request.GET.get('mime_type')  # Filter by mime type (e.g., 'application/vnd.google-apps.spreadsheet')
        
        service = get_drive_service(user)
        
        # Build files request
        files_request = service.files().list(
            pageSize=max_results,
            fields="nextPageToken, files(id, name, mimeType, size, createdTime, modifiedTime, webViewLink)"
        )
        
        if page_token:
            files_request.pageToken(page_token)
        
        if mime_type:
            files_request.q(f"mimeType='{mime_type}'")
        
        results = files_request.execute()
        
        files = results.get('files', [])
        next_page_token = results.get('nextPageToken')
        
        return Response({
            'files': files,
            'total': len(files),
            'nextPageToken': next_page_token,
            'hasMore': bool(next_page_token)
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        print(f"[ERROR] drive_list_view: {str(e)}")
        import traceback
        traceback.print_exc()
        return Response(
            {'error': f'Failed to list Drive files: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


# ========== GOOGLE SHEETS API ENDPOINTS ==========

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def sheets_list_view(request):
    """List all Google Sheets"""
    try:
        user = request.user
        if not user.google_access_token:
            return Response(
                {'error': 'Google OAuth tokens not found. Please log in with Google.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        max_results = int(request.GET.get('max_results', 50))
        page_token = request.GET.get('page_token')
        
        service = get_drive_service(user)
        
        # Filter for Google Sheets only
        sheets_request = service.files().list(
            q="mimeType='application/vnd.google-apps.spreadsheet'",
            pageSize=max_results,
            fields="nextPageToken, files(id, name, mimeType, createdTime, modifiedTime, webViewLink)"
        )
        
        if page_token:
            sheets_request.pageToken(page_token)
        
        results = sheets_request.execute()
        
        files = results.get('files', [])
        next_page_token = results.get('nextPageToken')
        
        return Response({
            'files': files,
            'total': len(files),
            'nextPageToken': next_page_token,
            'hasMore': bool(next_page_token)
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        print(f"[ERROR] sheets_list_view: {str(e)}")
        import traceback
        traceback.print_exc()
        return Response(
            {'error': f'Failed to list spreadsheets: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def sheets_read_view(request):
    """Read data from a Google Sheet"""
    try:
        user = request.user
        if not user.google_access_token:
            return Response(
                {'error': 'Google OAuth tokens not found. Please log in with Google.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        spreadsheet_id = request.GET.get('spreadsheet_id')
        range_name = request.GET.get('range', 'A1:B10')
        
        if not spreadsheet_id:
            return Response(
                {'error': 'Missing required parameter: spreadsheet_id'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        service = get_sheets_service(user)
        result = service.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id,
            range=range_name
        ).execute()
        
        values = result.get('values', [])
        
        return Response({
            'range': result.get('range', ''),
            'values': values,
            'total_rows': len(values)
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        print(f"[ERROR] sheets_read_view: {str(e)}")
        import traceback
        traceback.print_exc()
        return Response(
            {'error': f'Failed to read spreadsheet: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


# ========== GOOGLE DOCS API ENDPOINTS ==========

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def docs_list_view(request):
    """List all Google Docs"""
    try:
        user = request.user
        if not user.google_access_token:
            return Response(
                {'error': 'Google OAuth tokens not found. Please log in with Google.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        max_results = int(request.GET.get('max_results', 50))
        page_token = request.GET.get('page_token')
        
        service = get_drive_service(user)
        
        # Filter for Google Docs only
        docs_request = service.files().list(
            q="mimeType='application/vnd.google-apps.document'",
            pageSize=max_results,
            fields="nextPageToken, files(id, name, mimeType, createdTime, modifiedTime, webViewLink)"
        )
        
        if page_token:
            docs_request.pageToken(page_token)
        
        results = docs_request.execute()
        
        files = results.get('files', [])
        next_page_token = results.get('nextPageToken')
        
        return Response({
            'files': files,
            'total': len(files),
            'nextPageToken': next_page_token,
            'hasMore': bool(next_page_token)
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        print(f"[ERROR] docs_list_view: {str(e)}")
        import traceback
        traceback.print_exc()
        return Response(
            {'error': f'Failed to list documents: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def docs_read_view(request):
    """Read a Google Doc"""
    try:
        user = request.user
        if not user.google_access_token:
            return Response(
                {'error': 'Google OAuth tokens not found. Please log in with Google.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        document_id = request.GET.get('document_id')
        
        if not document_id:
            return Response(
                {'error': 'Missing required parameter: document_id'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        service = get_docs_service(user)
        document = service.documents().get(documentId=document_id).execute()
        
        # Extract text content
        content = document.get('body', {}).get('content', [])
        text_content = []
        
        def extract_text(element):
            if 'paragraph' in element:
                para = element['paragraph']
                if 'elements' in para:
                    for elem in para['elements']:
                        if 'textRun' in elem:
                            text_content.append(elem['textRun'].get('content', ''))
            elif 'table' in element:
                # Handle tables if needed
                pass
        
        for element in content:
            extract_text(element)
        
        return Response({
            'documentId': document.get('documentId', ''),
            'title': document.get('title', ''),
            'content': ''.join(text_content).strip()
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        print(f"[ERROR] docs_read_view: {str(e)}")
        import traceback
        traceback.print_exc()
        return Response(
            {'error': f'Failed to read document: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


# ========== AI API ENDPOINTS ==========

from .ai_service import (
    is_ai_available,
    analyze_email,
    generate_email_response,
    analyze_spreadsheet_data,
    analyze_document,
    general_chat,
)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def ai_status_view(request):
    """Check if AI service is available"""
    return Response({
        'available': is_ai_available()
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def ai_chat_view(request):
    """General AI chat endpoint"""
    try:
        if not is_ai_available():
            return Response(
                {'error': 'AI service is not configured. Please add OPENAI_API_KEY to environment variables.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        
        message = request.data.get('message')
        conversation_history = request.data.get('conversation_history', [])
        
        if not message:
            return Response(
                {'error': 'Missing required field: message'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        response = general_chat(message, conversation_history)
        
        return Response({
            'response': response
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        print(f"[ERROR] ai_chat_view: {str(e)}")
        import traceback
        traceback.print_exc()
        return Response(
            {'error': f'Failed to process chat request: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def ai_analyze_email_view(request):
    """Analyze an email using AI"""
    try:
        if not is_ai_available():
            return Response(
                {'error': 'AI service is not configured'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        
        email_content = request.data.get('content', '')
        subject = request.data.get('subject', '')
        from_sender = request.data.get('from', '')
        
        if not email_content:
            return Response(
                {'error': 'Missing required field: content'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        analysis = analyze_email(email_content, subject, from_sender)
        
        return Response(analysis, status=status.HTTP_200_OK)
        
    except Exception as e:
        print(f"[ERROR] ai_analyze_email_view: {str(e)}")
        import traceback
        traceback.print_exc()
        return Response(
            {'error': f'Failed to analyze email: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def ai_generate_email_response_view(request):
    """Generate an email response using AI"""
    try:
        if not is_ai_available():
            return Response(
                {'error': 'AI service is not configured'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        
        email_content = request.data.get('content', '')
        subject = request.data.get('subject', '')
        tone = request.data.get('tone', 'professional')
        
        if not email_content:
            return Response(
                {'error': 'Missing required field: content'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        response = generate_email_response(email_content, subject, tone)
        
        return Response({
            'response': response
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        print(f"[ERROR] ai_generate_email_response_view: {str(e)}")
        import traceback
        traceback.print_exc()
        return Response(
            {'error': f'Failed to generate email response: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def ai_analyze_spreadsheet_view(request):
    """Analyze spreadsheet data using AI"""
    try:
        if not is_ai_available():
            return Response(
                {'error': 'AI service is not configured'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        
        data = request.data.get('data', [])
        context = request.data.get('context', '')
        
        if not data:
            return Response(
                {'error': 'Missing required field: data'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        analysis = analyze_spreadsheet_data(data, context)
        
        return Response(analysis, status=status.HTTP_200_OK)
        
    except Exception as e:
        print(f"[ERROR] ai_analyze_spreadsheet_view: {str(e)}")
        import traceback
        traceback.print_exc()
        return Response(
            {'error': f'Failed to analyze spreadsheet: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def ai_analyze_document_view(request):
    """Analyze a document using AI"""
    try:
        if not is_ai_available():
            return Response(
                {'error': 'AI service is not configured'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        
        content = request.data.get('content', '')
        title = request.data.get('title', '')
        
        if not content:
            return Response(
                {'error': 'Missing required field: content'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        analysis = analyze_document(content, title)
        
        return Response(analysis, status=status.HTTP_200_OK)
        
    except Exception as e:
        print(f"[ERROR] ai_analyze_document_view: {str(e)}")
        import traceback
        traceback.print_exc()
        return Response(
            {'error': f'Failed to analyze document: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
