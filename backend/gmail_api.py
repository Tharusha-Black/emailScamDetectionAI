import os
import base64
from email import message_from_bytes
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

# Gmail API scope - read-only
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticate_gmail():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    # If no valid creds, force auth flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception as e:
                print("Refresh token failed. Forcing re-authentication.")
                os.remove("token.json")
                return authenticate_gmail()  # Recursively force fresh auth
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0, prompt='consent')
        # Save new token
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    return creds


def get_latest_emails(max_results=5):
    creds = authenticate_gmail()
    service = build('gmail', 'v1', credentials=creds)

    results = service.users().messages().list(userId='me', maxResults=max_results).execute()
    messages = results.get('messages', [])

    emails = []
    for msg in messages:
        msg_data = service.users().messages().get(userId='me', id=msg['id'], format='raw').execute()
        raw_data = base64.urlsafe_b64decode(msg_data['raw'].encode('ASCII'))
        email_msg = message_from_bytes(raw_data)

        subject = email_msg.get('Subject', '(No Subject)')
        sender = email_msg.get('From', '(No Sender)')
        body = get_body(email_msg)

        emails.append({
            'subject': subject,
            'from': sender,
            'body': body[:500]  # Limit for readability
        })

    return emails

def get_body(email_msg):
    if email_msg.is_multipart():
        for part in email_msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                return part.get_payload(decode=True).decode(errors='ignore')
    else:
        return email_msg.get_payload(decode=True).decode(errors='ignore')
    return ""

