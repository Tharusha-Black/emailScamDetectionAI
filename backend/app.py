from flask import Flask, jsonify, request
from gmail_api import get_latest_emails, authenticate_gmail
from spam_detection import predict_spam
import os
import json
from url_features_extractor import extract_all_features
from phishing_detection import predict_phishing
import re
import requests
from admin import init_db, create_admin_user, validate_login, save_scanned_email
from flask_cors import CORS
import sqlite3

app = Flask(__name__)
CORS(app)

PROCESSED_IDS_FILE = 'processed_ids.json'
init_db()

# Load processed email IDs
def load_processed_ids():
    if os.path.exists(PROCESSED_IDS_FILE):
        with open(PROCESSED_IDS_FILE, 'r') as f:
            return set(json.load(f))
    return set()

# Save processed email IDs
def save_processed_ids(ids):
    with open(PROCESSED_IDS_FILE, 'w') as f:
        json.dump(list(ids), f)


@app.route('/emails', methods=['GET'])
def fetch_and_classify_emails():
    processed_ids = load_processed_ids()
    new_emails = []
    seen_ids = set()

    creds = authenticate_gmail()
    from googleapiclient.discovery import build
    service = build('gmail', 'v1', credentials=creds)

    results = service.users().messages().list(userId='me', maxResults=10).execute()
    messages = results.get('messages', [])

    for msg in messages:
        msg_id = msg['id']
        if msg_id in processed_ids or msg_id in seen_ids:
            continue  # Skip already seen
        seen_ids.add(msg_id)

        msg_data = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()

        import base64
        from email import message_from_bytes
        raw_data = base64.urlsafe_b64decode(msg_data['raw'].encode('ASCII'))
        email_msg = message_from_bytes(raw_data)

        subject = email_msg.get('Subject', '(No Subject)')
        sender = email_msg.get('From', '(No Sender)')
        date = email_msg.get('Date', '(No Date)')
        body = get_body(email_msg)

        # Check for URLs in the email body
        urls = extract_urls_from_body(body)

        url_status = "URL not found"
        url_predictions = []

        if urls:
            for url in urls:
                # Call /check-url endpoint to get prediction
                prediction = check_url(url)
                url_predictions.append({'url': url, 'prediction': prediction})

            url_status = url_predictions

        spam_status = predict_spam(body)

        email_data = {
            'id': msg_id,
            'subject': subject,
            'from': sender,
            'date': date,
            'snippet': body[:300],
            'spam_status': spam_status,
            'url_status': url_status
        }

        # ✅ Save to database (additionally, without changing the response)
        save_scanned_email(email_data)

        new_emails.append(email_data)

    # Update processed ID cache
    processed_ids.update(seen_ids)
    save_processed_ids(processed_ids)

    return jsonify(new_emails)




@app.route('/scanned-emails', methods=['GET'])
def get_scanned_emails():
    conn = sqlite3.connect('spamDetection.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM scanned_emails ORDER BY date DESC")
    rows = c.fetchall()
    conn.close()

    emails = []
    for row in rows:
        email = dict(row)
        # Convert url_status back from JSON string to Python object
        try:
            email['url_status'] = json.loads(email['url_status'])
        except (json.JSONDecodeError, TypeError):
            email['url_status'] = "URL not found"
        emails.append(email)

    return jsonify(emails)


# Required: Extract plain text body from email
def get_body(email_msg):
    if email_msg.is_multipart():
        for part in email_msg.walk():
            if part.get_content_type() == 'text/plain':
                return part.get_payload(decode=True).decode(errors='ignore')
    else:
        return email_msg.get_payload(decode=True).decode(errors='ignore')
    return ""

# Function to extract URLs from the email body using regex
def extract_urls_from_body(body):
    url_pattern = r'(https?://[^\s]+)'  # Regex pattern to match http:// or https:// URLs
    urls = re.findall(url_pattern, body)
    print('extracted URL: ' , urls)
    return urls

# Check URL function that calls the /check-url endpoint
def check_url(url):
    # Send a POST request to the /check-url endpoint
    response = requests.post('http://127.0.0.1:5000/check-url', json={'url': url})
    if response.status_code == 200:
        return response.json().get('prediction', 'Error')
    else:
        return 'Error'

# New endpoint for phishing URL detection
@app.route('/check-url', methods=['POST'])
def check_url_endpoint():
    data = request.get_json()

    # Extract the URL from the JSON body
    url = data.get('url', '')

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    # If the URL starts with 'https://', consider it as legitimate
    if url.startswith('https://'):
        return jsonify({'url': url, 'prediction': 'Legitimate'})

    # Otherwise, extract features and classify the http:// URL
    features = extract_all_features(url)
    prediction = predict_phishing(features)

    return jsonify({'url': url, 'prediction': prediction})

# New endpoint for phishing URL detection
@app.route('/check-spam', methods=['POST'])
def check_spam():
    data = request.get_json()

    # Extract the URL from the JSON body
    msg = data.get('message', '')

    spam_status = predict_spam(msg)

    return jsonify({
        'message': msg, 
        'spam_status': spam_status
        })

@app.route('/create-user', methods=['POST'])
def create_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    success, message = create_admin_user(username, password)
    if success:
        return jsonify({'message': message}), 201
    else:
        return jsonify({'error': message}), 409

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    user_id = validate_login(username, password)
    if user_id:
        return jsonify({'message': 'Login successful', 'user_id': user_id})
    else:
        return jsonify({'error': 'Invalid username or password'}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
