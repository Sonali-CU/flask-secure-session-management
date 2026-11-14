import time
import secrets
import threading
from typing import Dict, Any, Optional, Tuple

class SessionStore:
    def __init__(self, inactivity_timeout: int = 120, absolute_timeout: int = 600):
        # Thread-safe in-memory session repository
        self._lock = threading.Lock()
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self.inactivity_timeout = inactivity_timeout
        self.absolute_timeout = absolute_timeout

    def generate_session_id(self) -> str:
        # Generates a 256-bit cryptographically secure, unpredictable token using os.urandom via secrets
        # token_urlsafe(32) yields 43 URL-safe base64 characters with 256 bits of CSPRNG entropy
        return secrets.token_urlsafe(32)

    def create_session(self, user_data: Dict[str, Any], ip_address: str = '', user_agent: str = '') -> str:
        session_id = self.generate_session_id()
        now = time.time()
        with self._lock:
            self._sessions[session_id] = {
                'user': user_data,
                'created_at': now,
                'last_activity': now,
                'ip_address': ip_address,
                'user_agent': user_agent,
                'authenticated': True
            }
        return session_id

    def create_prelogin_session(self, ip_address: str = '', user_agent: str = '') -> str:
        # Pre-login session for tracking unauthenticated visitors (e.g. CSRF tokens, cart)
        session_id = self.generate_session_id()
        now = time.time()
        with self._lock:
            self._sessions[session_id] = {
                'user': None,
                'created_at': now,
                'last_activity': now,
                'ip_address': ip_address,
                'user_agent': user_agent,
                'authenticated': False
            }
        return session_id

    def regenerate_session(self, old_session_id: Optional[str], new_user_data: Optional[Dict[str, Any]] = None,
                           ip_address: str = '', user_agent: str = '') -> str:
        # Regenerates session ID to prevent Session Fixation (Task 3, 9) and upon Privilege Changes (Task 14)
        new_session_id = self.generate_session_id()
        now = time.time()
        with self._lock:
            old_data = self._sessions.pop(old_session_id, None) if old_session_id else None
            user = new_user_data if new_user_data is not None else (old_data['user'] if old_data else None)
            created_at = old_data['created_at'] if (old_data and old_data.get('authenticated')) else now
            ip = ip_address or (old_data.get('ip_address') if old_data else '')
            ua = user_agent or (old_data.get('user_agent') if old_data else '')

            self._sessions[new_session_id] = {
                'user': user,
                'created_at': created_at,
                'last_activity': now,
                'ip_address': ip,
                'user_agent': ua,
                'authenticated': user is not None
            }
        return new_session_id

    def get_session(self, session_id: Optional[str], enforce_timeout: bool = True) -> Tuple[Optional[Dict[str, Any]], str]:
        if not session_id:
            return None, 'NO_SESSION'

        now = time.time()
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None, 'INVALID_SESSION'

            if enforce_timeout:
                # Check inactivity timeout (Task 4: default 2 minutes = 120s)
                if now - session['last_activity'] > self.inactivity_timeout:
                    self._sessions.pop(session_id, None)
                    return None, 'EXPIRED_INACTIVITY'

                # Check absolute timeout (Task 4: default 10 minutes = 600s)
                if now - session['created_at'] > self.absolute_timeout:
                    self._sessions.pop(session_id, None)
                    return None, 'EXPIRED_ABSOLUTE'

            # Touch last_activity
            session['last_activity'] = now
            return session, 'ACTIVE'

    def invalidate_session(self, session_id: Optional[str]) -> bool:
        # Task 5: Server-side invalidation
        if not session_id:
            return False
        with self._lock:
            return self._sessions.pop(session_id, None) is not None

    def validate_client_fingerprint(self, session_id: str, ip_address: str, user_agent: str) -> bool:
        # Task 13: Detect session hijacking via client fingerprinting
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False
            if session.get('user_agent') and session.get('user_agent') != user_agent:
                return False
            return True

    def count_active_sessions(self) -> int:
        with self._lock:
            return len(self._sessions)
