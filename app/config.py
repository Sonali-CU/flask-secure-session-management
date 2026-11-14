import os
import secrets
from werkzeug.security import generate_password_hash

class Config:
    # High-entropy secret key for cryptographic operations
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    
    # Cookie security attributes
    SESSION_COOKIE_NAME = 'secure_session_token'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() in ('true', '1', 'yes')
    SESSION_COOKIE_SAMESITE = os.environ.get('SESSION_COOKIE_SAMESITE', 'Strict')
    
    # Session timeout configuration (Task 4)
    # 2 minutes of inactivity timeout
    SESSION_INACTIVITY_TIMEOUT = int(os.environ.get('SESSION_INACTIVITY_TIMEOUT', 120))
    # 10 minutes absolute lifetime from session creation
    SESSION_ABSOLUTE_TIMEOUT = int(os.environ.get('SESSION_ABSOLUTE_TIMEOUT', 600))
    
    # Demo and evaluation user accounts with argon2 / pbkdf2 werkzeug hashes
    USERS = {
        'sonali': {
            'username': 'sonali',
            'password_hash': generate_password_hash('SonaliSecure@2026!'),
            'role': 'user',
            'full_name': 'Sonali Gupta'
        },
        'bob': {
            'username': 'bob',
            'password_hash': generate_password_hash('BobUserPass#456'),
            'role': 'user',
            'full_name': 'Bob Smith'
        },
        'admin': {
            'username': 'admin',
            'password_hash': generate_password_hash('SuperAdminKey$999'),
            'role': 'admin',
            'full_name': 'System Administrator'
        }
    }
