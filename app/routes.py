import time
from functools import wraps
from flask import (
    Blueprint, render_template, request, redirect, url_for,
    jsonify, current_app, make_response
)
from werkzeug.security import check_password_hash

main_bp = Blueprint('main', __name__)

def get_current_session():
    cookie_name = current_app.config['SESSION_COOKIE_NAME']
    session_id = request.cookies.get(cookie_name)
    if not session_id:
        return None, None, 'NO_COOKIE'
    
    session, status = current_app.session_store.get_session(session_id)
    return session_id, session, status

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_id, session, status = get_current_session()
        if not session or not session.get('authenticated'):
            resp = redirect(url_for('main.login', reason=status))
            if session_id:
                resp.delete_cookie(current_app.config['SESSION_COOKIE_NAME'], path='/')
            return resp
        return f(*args, **kwargs)
    return decorated_function

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            session_id, session, status = get_current_session()
            if not session or not session.get('authenticated'):
                return redirect(url_for('main.login', reason=status))
            user = session.get('user', {})
            if user.get('role') != required_role:
                # HTTP 403 Forbidden for insufficient privileges (Task 14)
                return render_template(
                    'error.html',
                    title='Access Denied (403)',
                    message='Role ' + required_role + ' required. Your current role is ' + str(user.get('role')) + '.'
                ), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@main_bp.route('/')
def index():
    _, session, _ = get_current_session()
    if session and session.get('authenticated'):
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('main.login'))

@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    cookie_name = current_app.config['SESSION_COOKIE_NAME']
    existing_session_id = request.cookies.get(cookie_name)
    
    # Pre-login session creation if not present (tracks anonymous visitors/CSRF)
    prelogin_id = existing_session_id
    needs_prelogin_cookie = False
    if not prelogin_id:
        prelogin_id = current_app.session_store.create_prelogin_session(
            ip_address=request.remote_addr or '',
            user_agent=request.headers.get('User-Agent', '')
        )
        needs_prelogin_cookie = True

    if request.method == 'GET':
        reason = request.args.get('reason')
        message = None
        if reason == 'EXPIRED_INACTIVITY':
            message = 'Your session expired due to inactivity (2 minutes timeout).'
        elif reason == 'EXPIRED_ABSOLUTE':
            message = 'Your session reached its maximum absolute lifetime (10 minutes timeout).'
        elif reason == 'logged_out':
            message = 'You have successfully logged out. Session invalidated.'

        resp = make_response(render_template('login.html', message=message, prelogin_id=prelogin_id))
        if needs_prelogin_cookie:
            resp.set_cookie(
                cookie_name,
                prelogin_id,
                httponly=current_app.config['SESSION_COOKIE_HTTPONLY'],
                secure=current_app.config['SESSION_COOKIE_SECURE'],
                samesite=current_app.config['SESSION_COOKIE_SAMESITE'],
                path='/'
            )
        return resp

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    user_record = current_app.config['USERS'].get(username)
    if not user_record or not check_password_hash(user_record['password_hash'], password):
        return render_template('login.html', error='Invalid username or password.', prelogin_id=prelogin_id), 401

    # Task 3 & 9: Immediately regenerate session identifier upon successful authentication
    # This destroys the pre-login session ID and generates a new random token, preventing Session Fixation
    user_payload = {
        'username': user_record['username'],
        'role': user_record['role'],
        'full_name': user_record['full_name']
    }
    
    new_session_id = current_app.session_store.regenerate_session(
        old_session_id=existing_session_id,
        new_user_data=user_payload,
        ip_address=request.remote_addr or '',
        user_agent=request.headers.get('User-Agent', '')
    )

    # Task 6, 7, 8, 10: Store session ID in secure cookies, NEVER in URLs
    resp = redirect(url_for('main.dashboard'))
    resp.set_cookie(
        cookie_name,
        new_session_id,
        httponly=current_app.config['SESSION_COOKIE_HTTPONLY'],
        secure=current_app.config['SESSION_COOKIE_SECURE'],
        samesite=current_app.config['SESSION_COOKIE_SAMESITE'],
        path='/'
    )
    return resp

@main_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    # Task 5: Complete session invalidation
    cookie_name = current_app.config['SESSION_COOKIE_NAME']
    session_id = request.cookies.get(cookie_name)
    
    if session_id:
        current_app.session_store.invalidate_session(session_id)

    resp = redirect(url_for('main.login', reason='logged_out'))
    # Delete cookie on client browser
    resp.delete_cookie(cookie_name, path='/')
    return resp

@main_bp.route('/dashboard')
@login_required
def dashboard():
    session_id, session, _ = get_current_session()
    now = time.time()
    user = session['user']
    
    # Calculate timeout counters (Task 4)
    inactivity_limit = current_app.session_store.inactivity_timeout
    absolute_limit = current_app.session_store.absolute_timeout
    inactivity_remaining = max(0, int(inactivity_limit - (now - session['last_activity'])))
    absolute_remaining = max(0, int(absolute_limit - (now - session['created_at'])))

    return render_template(
        'dashboard.html',
        user=user,
        session_id_preview=session_id[:8] + '...' + session_id[-6:],
        full_session_id=session_id,
        inactivity_remaining=inactivity_remaining,
        absolute_remaining=absolute_remaining,
        cookie_secure=current_app.config['SESSION_COOKIE_SECURE'],
        cookie_httponly=current_app.config['SESSION_COOKIE_HTTPONLY'],
        cookie_samesite=current_app.config['SESSION_COOKIE_SAMESITE']
    )

@main_bp.route('/admin')
@role_required('admin')
def admin_panel():
    session_id, session, _ = get_current_session()
    return render_template(
        'admin.html',
        user=session['user'],
        active_sessions_count=current_app.session_store.count_active_sessions()
    )

@main_bp.route('/elevate-privilege', methods=['POST'])
@login_required
def elevate_privilege():
    # Task 14: Regenerate session identifier when privilege/role changes
    cookie_name = current_app.config['SESSION_COOKIE_NAME']
    session_id, session, _ = get_current_session()
    
    updated_user = dict(session['user'])
    updated_user['role'] = 'admin'
    
    # Regenerate session ID upon privilege change to prevent session privilege escalation attacks
    new_session_id = current_app.session_store.regenerate_session(
        old_session_id=session_id,
        new_user_data=updated_user,
        ip_address=request.remote_addr or '',
        user_agent=request.headers.get('User-Agent', '')
    )
    
    resp = redirect(url_for('main.admin_panel'))
    resp.set_cookie(
        cookie_name,
        new_session_id,
        httponly=current_app.config['SESSION_COOKIE_HTTPONLY'],
        secure=current_app.config['SESSION_COOKIE_SECURE'],
        samesite=current_app.config['SESSION_COOKIE_SAMESITE'],
        path='/'
    )
    return resp

@main_bp.route('/test-cookie-access')
@login_required
def test_cookie_access():
    # Task 7: Demonstrating that document.cookie cannot access HttpOnly session cookie
    cookie_name = current_app.config['SESSION_COOKIE_NAME']
    return render_template('test_cookie.html', cookie_name=cookie_name)

@main_bp.route('/samesite-demo')
def samesite_demo():
    # Task 8: Explaining and testing SameSite policy effects
    current_policy = current_app.config['SESSION_COOKIE_SAMESITE']
    return render_template('samesite_demo.html', current_policy=current_policy)

@main_bp.route('/api/session-status')
def api_session_status():
    session_id, session, status = get_current_session()
    if not session:
        return jsonify({
            'authenticated': False,
            'status': status,
            'message': 'No active session found or session has expired.'
        }), 401
    
    now = time.time()
    inactivity_rem = max(0, current_app.session_store.inactivity_timeout - (now - session['last_activity']))
    absolute_rem = max(0, current_app.session_store.absolute_timeout - (now - session['created_at']))
    
    return jsonify({
        'authenticated': True,
        'status': status,
        'username': session['user']['username'],
        'role': session['user']['role'],
        'inactivity_remaining_seconds': inactivity_rem,
        'absolute_remaining_seconds': absolute_rem,
        'session_id_prefix': session_id[:8] if session_id else None
    }), 200
