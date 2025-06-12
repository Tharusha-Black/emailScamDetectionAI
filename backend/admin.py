import sqlite3
import hashlib
import json

DB_NAME = 'spamDetection.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS scanned_emails (
            id TEXT PRIMARY KEY,
            subject TEXT,
            sender TEXT,
            date TEXT,
            snippet TEXT,
            spam_status TEXT,
            url_status TEXT
        )
    ''')
    conn.commit()
    conn.close()


def save_scanned_email(email_data):
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''
            INSERT OR REPLACE INTO scanned_emails
            (id, subject, sender, date, snippet, spam_status, url_status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            email_data['id'],
            email_data['subject'],
            email_data['from'],
            email_data['date'],
            email_data['snippet'],
            email_data['spam_status'],
            json.dumps(email_data['url_status'])  # store list/dict as JSON
        ))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[DB Error] Failed to save email {email_data['id']}: {e}")
        return False


def create_admin_user(username, password):
    hashed = hashlib.md5(password.encode()).hexdigest()
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("INSERT INTO admin (username, password) VALUES (?, ?)", (username, hashed))
        conn.commit()
        conn.close()
        return True, "User created"
    except sqlite3.IntegrityError:
        return False, "Username already exists"

def validate_login(username, password):
    hashed = hashlib.md5(password.encode()).hexdigest()
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id FROM admin WHERE username = ? AND password = ?", (username, hashed))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None
