import time
import math
import secrets
from collections import Counter
import pytest
from app.session_store import SessionStore

# --- Task 1: Secure Session Creation ---
def test_task01_secure_session_creation(client):
    # GET login page
    res_get = client.get('/login')
    assert res_get.status_code == 200
    
    # POST valid login credentials for alice
    res_post = client.post('/login', data={'username': 'sonali', 'password': 'SonaliSecure@2026!'}, follow_redirects=False)
    assert res_post.status_code == 302
    assert res_post.headers['Location'].endswith('/dashboard')
    
    # Cookie must be set in response
    cookies = res_post.headers.getlist('Set-Cookie')
    assert any('secure_session_token=' in c for c in cookies)
    
    # Access dashboard with session
    res_dash = client.get('/dashboard')
    assert res_dash.status_code == 200
    assert b'Sonali Gupta' in res_dash.data
    assert b'Role: USER' in res_dash.data

# --- Task 2: Unpredictable Session Identifiers ---
def test_task02_unpredictable_session_identifiers():
    store = SessionStore()
    tokens = [store.generate_session_id() for _ in range(1000)]
    
    # Verify zero collisions
    assert len(tokens) == len(set(tokens)), "Collision detected in generated session IDs!"
    
    # Verify high Shannon entropy across tokens
    sample = "".join(tokens)
    freqs = Counter(sample)
    entropy = -sum((c / len(sample)) * math.log2(c / len(sample)) for c in freqs.values())
    
    # Base64url alphabet has 64 symbols; theoretical max entropy is 6.0 bits/char
    assert entropy >= 5.5, f"Entropy too low: {entropy:.2f} bits/character"
    
    # Verify sequential difference
    for i in range(len(tokens) - 1):
        assert tokens[i] != tokens[i+1]
        assert len(tokens[i]) >= 43 # 32 bytes base64url encoded

# --- Task 3: Session ID Regeneration ---
def test_task03_session_id_regeneration(client, app):
    # Obtain pre-login session cookie
    res_pre = client.get('/login')
    pre_cookie = None
    for c in res_pre.headers.getlist('Set-Cookie'):
        if 'secure_session_token=' in c:
            pre_cookie = c.split(';')[0].split('=')[1]
            break
    assert pre_cookie is not None
    
    # Login as alice
    res_login = client.post('/login', data={'username': 'sonali', 'password': 'SonaliSecure@2026!'}, follow_redirects=False)
    post_cookie = None
    for c in res_login.headers.getlist('Set-Cookie'):
        if 'secure_session_token=' in c:
            post_cookie = c.split(';')[0].split('=')[1]
            break
            
    assert post_cookie is not None
    # Crucial: Pre-login and post-login IDs must NOT match
    assert pre_cookie != post_cookie
    
    # Crucial: Pre-login session ID must be completely invalidated and cannot access dashboard
    client.set_cookie('secure_session_token', pre_cookie)
    res_attacker = client.get('/dashboard', follow_redirects=False)
    assert res_attacker.status_code == 302
    assert '/login' in res_attacker.headers['Location']

# --- Task 4: Session Expiration & Timeout ---
def test_task04_session_expiration_timeout():
    # Test inactivity timeout (configured to 1s for fast automated test)
    quick_store = SessionStore(inactivity_timeout=1, absolute_timeout=10)
    sid = quick_store.create_session({'username': 'sonali', 'role': 'user'})
    
    # Immediate check -> ACTIVE
    session, status = quick_store.get_session(sid)
    assert status == 'ACTIVE'
    assert session is not None
    
    # Wait 1.1s for inactivity timeout
    time.sleep(1.1)
    session_expired, status_expired = quick_store.get_session(sid)
    assert status_expired == 'EXPIRED_INACTIVITY'
    assert session_expired is None
    
    # Test absolute timeout (configured to 2s, but continuous activity)
    abs_store = SessionStore(inactivity_timeout=5, absolute_timeout=2)
    sid_abs = abs_store.create_session({'username': 'sonali', 'role': 'user'})
    
    # Repeated access within inactivity limit
    time.sleep(0.8)
    s1, st1 = abs_store.get_session(sid_abs)
    assert st1 == 'ACTIVE'
    
    time.sleep(1.3) # Total elapsed > 2.0s
    s2, st2 = abs_store.get_session(sid_abs)
    assert st2 == 'EXPIRED_ABSOLUTE'
    assert s2 is None

# --- Task 5: Session Invalidation After Logout ---
def test_task05_session_invalidation_after_logout(client, app):
    # Login
    res_login = client.post('/login', data={'username': 'sonali', 'password': 'SonaliSecure@2026!'}, follow_redirects=False)
    session_cookie = None
    for c in res_login.headers.getlist('Set-Cookie'):
        if 'secure_session_token=' in c:
            session_cookie = c.split(';')[0].split('=')[1]
            break
            
    # Verify active in store
    sess, st = app.session_store.get_session(session_cookie)
    assert st == 'ACTIVE'
    
    # Logout
    res_logout = client.get('/logout', follow_redirects=False)
    assert res_logout.status_code == 302
    
    # Verify cookie deleted in Set-Cookie response header (Max-Age=0 or Expires in past)
    del_cookie = res_logout.headers.get('Set-Cookie')
    assert 'secure_session_token=;' in del_cookie or 'Max-Age=0' in del_cookie or 'expires=Thu, 01 Jan 1970' in del_cookie
    
    # Verify session completely destroyed on server
    sess_after, st_after = app.session_store.get_session(session_cookie)
    assert sess_after is None
    assert st_after == 'INVALID_SESSION'
    
    # Attempt to access dashboard using previous session token
    client.set_cookie('secure_session_token', session_cookie)
    res_dash = client.get('/dashboard', follow_redirects=False)
    assert res_dash.status_code == 302
    assert '/login' in res_dash.headers['Location']

# --- Task 6: Secure Cookie Configuration ---
def test_task06_secure_cookie_configuration(client):
    res = client.post('/login', data={'username': 'sonali', 'password': 'SonaliSecure@2026!'}, follow_redirects=False)
    cookie_headers = res.headers.getlist('Set-Cookie')
    
    secure_found = False
    for header in cookie_headers:
        if 'secure_session_token=' in header:
            attrs = [part.strip().lower() for part in header.split(';')]
            if 'secure' in attrs:
                secure_found = True
                
    assert secure_found, "Secure attribute must be configured on session cookie!"

# --- Task 7: HttpOnly Cookie Configuration ---
def test_task07_httponly_cookie_configuration(client):
    res = client.post('/login', data={'username': 'sonali', 'password': 'SonaliSecure@2026!'}, follow_redirects=False)
    cookie_headers = res.headers.getlist('Set-Cookie')
    
    httponly_found = False
    for header in cookie_headers:
        if 'secure_session_token=' in header:
            attrs = [part.strip().lower() for part in header.split(';')]
            if 'httponly' in attrs:
                httponly_found = True
                
    assert httponly_found, "HttpOnly attribute must be configured on session cookie!"

# --- Task 8: SameSite Cookie Policy ---
def test_task08_samesite_cookie_policy(client):
    res = client.post('/login', data={'username': 'sonali', 'password': 'SonaliSecure@2026!'}, follow_redirects=False)
    cookie_headers = res.headers.getlist('Set-Cookie')
    
    samesite_val = None
    for header in cookie_headers:
        if 'secure_session_token=' in header:
            for part in header.split(';'):
                if 'samesite=' in part.strip().lower():
                    samesite_val = part.strip().split('=')[1]
                    
    assert samesite_val is not None
    assert samesite_val.capitalize() in ['Strict', 'Lax', 'None']
    assert samesite_val.capitalize() == 'Strict'

# --- Task 9: Session Fixation Prevention ---
def test_task09_session_fixation_prevention(client, app):
    # Attacker sets up a fixed session identifier
    attacker_fixed_sid = 'ATTACKER_INJECTED_FIXED_SESSION_TOKEN_12345'
    app.session_store.create_prelogin_session()
    
    # Inject attacker fixed session into client cookie
    client.set_cookie('secure_session_token', attacker_fixed_sid)
    
    # Victim logs in using the session
    res_login = client.post('/login', data={'username': 'sonali', 'password': 'SonaliSecure@2026!'}, follow_redirects=False)
    
    victim_sid = None
    for c in res_login.headers.getlist('Set-Cookie'):
        if 'secure_session_token=' in c:
            victim_sid = c.split(';')[0].split('=')[1]
            break
            
    # Server must NOT keep attacker_fixed_sid; it must generate a brand new victim_sid
    assert victim_sid != attacker_fixed_sid
    
    # Attacker tries to use their fixed sid to access dashboard
    client.set_cookie('secure_session_token', attacker_fixed_sid)
    res_attack = client.get('/dashboard', follow_redirects=False)
    assert res_attack.status_code == 302
    assert '/login' in res_attack.headers['Location']

# --- Task 10: Prevent Session IDs in URLs ---
def test_task10_prevent_session_ids_in_urls(client):
    # Login
    res = client.post('/login', data={'username': 'sonali', 'password': 'SonaliSecure@2026!'}, follow_redirects=True)
    
    # Check current redirected URL: must NOT contain session ID parameters
    assert 'session_id' not in res.request.url
    assert 'token' not in res.request.url
    assert 'sid' not in res.request.url
    
    # Attempting to supply session in query string must NOT authenticate request
    res_url_auth = client.get('/dashboard?secure_session_token=fake_or_leaked_token', follow_redirects=False)
    # The application reads from request.cookies, never request.args
    assert res_url_auth.status_code == 200 # authenticates via cookie, ignoring query param

# --- Task 13: Session Hijacking Simulation ---
def test_task13_session_hijacking_simulation(client, app):
    # Valid user logs in with legitimate User-Agent
    res_login = client.post(
        '/login',
        data={'username': 'sonali', 'password': 'SonaliSecure@2026!'},
        headers={'User-Agent': 'LegitimateBrowser/1.0 (Windows NT 10.0)'},
        follow_redirects=False
    )
    user_sid = None
    for c in res_login.headers.getlist('Set-Cookie'):
        if 'secure_session_token=' in c:
            user_sid = c.split(';')[0].split('=')[1]
            break
            
    # Hijacker copies session token but presents an attacker User-Agent
    hijacker_ua = 'MaliciousScript/2.0 (KaliLinux)'
    is_valid_hijack = app.session_store.validate_client_fingerprint(user_sid, '192.168.1.100', hijacker_ua)
    assert is_valid_hijack is False, "Session hijacking via different user agent fingerprint must be detected!"
    
    # Also verify that a forged/random stolen token is rejected
    forged_sid = 'FORGED_COOKIE_' + secrets.token_hex(16)
    sess, st = app.session_store.get_session(forged_sid)
    assert sess is None
    assert st == 'INVALID_SESSION'

# --- Task 14: Role-Based Session Management & Privilege Regeneration ---
def test_task14_role_based_session_management(client, app):
    # 1. Normal user alice logs in
    client.post('/login', data={'username': 'sonali', 'password': 'SonaliSecure@2026!'}, follow_redirects=True)
    
    # Alice can access /dashboard
    res_dash = client.get('/dashboard')
    assert res_dash.status_code == 200
    
    # Alice CANNOT access /admin (403 Forbidden)
    res_admin_denied = client.get('/admin')
    assert res_admin_denied.status_code == 403
    assert b'Access Denied (403)' in res_admin_denied.data
    
    # Capture pre-elevation session ID
    pre_elev_sid = client.get_cookie('secure_session_token').value
    
    # 2. Elevate alice's privilege to admin
    res_elev = client.post('/elevate-privilege', follow_redirects=False)
    assert res_elev.status_code == 302
    assert res_elev.headers['Location'].endswith('/admin')
    
    # Capture post-elevation session ID
    post_elev_sid = None
    for c in res_elev.headers.getlist('Set-Cookie'):
        if 'secure_session_token=' in c:
            post_elev_sid = c.split(';')[0].split('=')[1]
            break
            
    # CRITICAL: Session ID must be regenerated upon privilege elevation!
    assert post_elev_sid is not None
    assert post_elev_sid != pre_elev_sid
    
    # Old pre-elevation session ID must be dead
    old_sess, old_st = app.session_store.get_session(pre_elev_sid)
    assert old_sess is None
    
    # Alice now has admin clearance with the new session ID
    res_admin_allowed = client.get('/admin')
    assert res_admin_allowed.status_code == 200
    assert b'System Administration Control Panel' in res_admin_allowed.data
