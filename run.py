import os
import argparse
import ssl
from app import create_app, session_store
from app.config import Config

def main():
    parser = argparse.ArgumentParser(description='Run Secure Session Management Application')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind')
    parser.add_argument('--https', action='store_true', help='Enable HTTPS mode with SSL certificate')
    parser.add_argument('--secure-cookie', action='store_true', help='Force Secure cookie attribute')
    parser.add_argument('--samesite', default=None, choices=['Strict', 'Lax', 'None'], help='Override SameSite policy')
    parser.add_argument('--inactivity-timeout', type=int, default=120, help='Inactivity timeout in seconds (default: 120)')
    parser.add_argument('--absolute-timeout', type=int, default=600, help='Absolute timeout in seconds (default: 600)')
    
    args = parser.parse_args()

    class RuntimeConfig(Config):
        SESSION_INACTIVITY_TIMEOUT = args.inactivity_timeout
        SESSION_ABSOLUTE_TIMEOUT = args.absolute_timeout
        if args.samesite:
            SESSION_COOKIE_SAMESITE = args.samesite
        if args.https or args.secure_cookie:
            SESSION_COOKIE_SECURE = True

    # Configure session store timeouts
    session_store.inactivity_timeout = args.inactivity_timeout
    session_store.absolute_timeout = args.absolute_timeout

    app = create_app(RuntimeConfig)

    ssl_context = None
    protocol = "http"
    if args.https:
        protocol = "https"
        cert_path = os.path.join(os.path.dirname(__file__), 'certs', 'cert.pem')
        key_path = os.path.join(os.path.dirname(__file__), 'certs', 'key.pem')
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            raise FileNotFoundError("SSL certificates not found in certs/. Run certs/generate_certs.py first.")
        ssl_context = (cert_path, key_path)

    print("=" * 65)
    print(f"🔒 Secure Session Management Lab Server Starting")
    print(f"   URL: {protocol}://{args.host}:{args.port}")
    print(f"   Inactivity Timeout: {args.inactivity_timeout}s (2 minutes)")
    print(f"   Absolute Timeout:   {args.absolute_timeout}s (10 minutes)")
    print(f"   Cookie Attributes:  HttpOnly={app.config['SESSION_COOKIE_HTTPONLY']}, Secure={app.config['SESSION_COOKIE_SECURE']}, SameSite={app.config['SESSION_COOKIE_SAMESITE']}")
    print("=" * 65)

    app.run(host=args.host, port=args.port, ssl_context=ssl_context, debug=False)

if __name__ == '__main__':
    main()
