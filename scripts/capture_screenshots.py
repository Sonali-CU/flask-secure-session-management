import os
import sys
import time
import threading
from werkzeug.serving import make_server
from selenium import webdriver
from selenium.webdriver.edge.options import Options as EdgeOptions
from selenium.webdriver.common.by import By

# Fix encoding
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

base = r'C:\Users\DELL\Downloads\flask-secure-session-management'
screenshots_dir = os.path.join(base, 'screenshots')
os.makedirs(screenshots_dir, exist_ok=True)

# Import app
sys.path.insert(0, base)
from app import create_app
from app.config import Config
from app.session_store import SessionStore

class ServerThread(threading.Thread):
    def __init__(self, app, port=5057):
        super().__init__()
        self.server = make_server('127.0.0.1', port, app)
        self.ctx = app.app_context()
        self.ctx.push()
        self.daemon = True

    def run(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()

def capture_all():
    print("Starting application for screenshot capture...")
    class ScreenConfig(Config):
        SESSION_COOKIE_SECURE = False  # Allows headless HTTP capture locally
        SESSION_COOKIE_HTTPONLY = True
        SESSION_COOKIE_SAMESITE = 'Strict'
        SESSION_INACTIVITY_TIMEOUT = 120
        SESSION_ABSOLUTE_TIMEOUT = 600

    store = SessionStore(inactivity_timeout=120, absolute_timeout=600)
    app = create_app(ScreenConfig)
    app.session_store = store

    server = ServerThread(app, port=5057)
    server.start()
    time.sleep(1.5)

    base_url = "http://127.0.0.1:5057"

    edge_options = EdgeOptions()
    edge_options.add_argument('--headless=new')
    edge_options.add_argument('--window-size=1280,850')
    edge_options.add_argument('--disable-gpu')

    print("Initializing Edge headless browser...")
    driver = webdriver.Edge(options=edge_options)

    try:
        # 1. Login Page
        print("Capturing 01_login_page.png...")
        driver.get(f"{base_url}/login")
        time.sleep(1)
        driver.save_screenshot(os.path.join(screenshots_dir, '01_login_page.png'))

        # 2. Perform Login as Alice
        print("Logging in as alice...")
        user_input = driver.find_element(By.ID, 'username')
        pass_input = driver.find_element(By.ID, 'password')
        user_input.send_keys('alice')
        pass_input.send_keys('AliceUser@2026!')
        driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]').click()
        time.sleep(1.5)

        # 3. User Dashboard
        print("Capturing 02_user_dashboard.png...")
        driver.save_screenshot(os.path.join(screenshots_dir, '02_user_dashboard.png'))

        # 4. HttpOnly JavaScript Inspection
        print("Capturing 03_httponly_cookie_inspection.png...")
        driver.get(f"{base_url}/test-cookie-access")
        time.sleep(1)
        driver.save_screenshot(os.path.join(screenshots_dir, '03_httponly_cookie_inspection.png'))

        # 5. SameSite Policy Matrix
        print("Capturing 04_samesite_policy_matrix.png...")
        driver.get(f"{base_url}/samesite-demo")
        time.sleep(1)
        driver.save_screenshot(os.path.join(screenshots_dir, '04_samesite_policy_matrix.png'))

        # 6. Attempt direct Admin access (Normal User -> 403 Forbidden)
        print("Capturing 05_access_denied_403.png...")
        driver.get(f"{base_url}/admin")
        time.sleep(1)
        driver.save_screenshot(os.path.join(screenshots_dir, '05_access_denied_403.png'))

        # 7. Elevate Privilege to Admin
        print("Elevating privilege to admin...")
        driver.get(f"{base_url}/dashboard")
        time.sleep(1)
        driver.find_element(By.CSS_SELECTOR, 'button.btn-warning').click()
        time.sleep(1.5)

        # 8. Admin Panel
        print("Capturing 06_admin_panel_rbac.png...")
        driver.save_screenshot(os.path.join(screenshots_dir, '06_admin_panel_rbac.png'))

        print("All screenshots successfully captured!")
    finally:
        driver.quit()
        server.shutdown()

if __name__ == '__main__':
    capture_all()
