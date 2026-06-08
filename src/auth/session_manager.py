"""Session lifecycle management for SecureCloud Database Proxy.

Provides thread-safe session creation, validation, and expiry for
concurrent multi-user access with JWT-like signed session tokens.
"""

import os
import time
import uuid
import hmac
import hashlib
import threading
from typing import Dict, Optional
from dataclasses import dataclass, field

from src.auth.rbac import Role

SESSION_TTL_SECONDS = 3600  # 1 hour default
ROTATION_INTERVAL = 900      # Rotate nonce every 15 minutes
TOKEN_SECRET_KEY = os.environ.get("SESSION_SECRET", os.urandom(32).hex())


@dataclass
class Session:
      session_id: str
      user_id: str
      role: Role
      created_at: float
      expires_at: float
      nonce: str = field(default_factory=lambda: uuid.uuid4().hex)
      is_valid: bool = True

    def is_expired(self) -> bool:
              return time.time() > self.expires_at

    def should_rotate(self) -> bool:
              return (time.time() - self.created_at) > ROTATION_INTERVAL


def _sign_token(session_id: str, user_id: str, expires_at: float, nonce: str) -> str:
      """Create an HMAC-SHA256 signature for a session token."""
      payload = f"{session_id}:{user_id}:{expires_at:.0f}:{nonce}"
      secret = TOKEN_SECRET_KEY.encode() if isinstance(TOKEN_SECRET_KEY, str) else TOKEN_SECRET_KEY
    return hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()


def _build_token(session: Session) -> str:
      """Encode a session into a signed token string."""
      sig = _sign_token(session.session_id, session.user_id, session.expires_at, session.nonce)
      parts = [
          session.session_id,
          session.user_id,
          session.role.value,
          str(int(session.expires_at)),
          session.nonce,
          sig,
      ]
      return ".".join(parts)


class SessionManager:
      """Thread-safe session store with automatic TTL expiry.

          Uses a concurrent-safe dict with a read-write lock pattern. Session
              invalidation is local to this instance; in a distributed setup,
                  propagate invalidations via a pub/sub channel.
                      """

    def __init__(self, ttl: int = SESSION_TTL_SECONDS):
              self._sessions: Dict[str, Session] = {}
              self._lock = threading.RLock()
              self._ttl = ttl
              self._start_sweep_thread()

    def create_session(self, user_id: str, role: Role) -> str:
              """Create a new session and return a signed token."""
              session_id = uuid.uuid4().hex
              now = time.time()
              session = Session(
                  session_id=session_id,
                  user_id=user_id,
                  role=role,
                  created_at=now,
                  expires_at=now + self._ttl,
              )
              with self._lock:
                            self._sessions[session_id] = session
                        return _build_token(session)

    def validate_token(self, token: str) -> Optional[Session]:
              """Validate a session token and return the Session if valid."""
        try:
                      parts = token.split(".")
                      if len(parts) != 6:
                                        return None
                                    session_id, user_id, role_val, exp_str, nonce, provided_sig = parts
            expected_sig = _sign_token(session_id, user_id, float(exp_str), nonce)
            if not hmac.compare_digest(expected_sig, provided_sig):
                              return None
except Exception:
            return None

        with self._lock:
                      session = self._sessions.get(session_id)
            if session is None or not session.is_valid or session.is_expired():
                              return None
                          return session

    def invalidate(self, session_id: str) -> None:
              """Invalidate a session immediately."""
        with self._lock:
                      if session_id in self._sessions:
                                        self._sessions[session_id].is_valid = False

    def invalidate_user(self, user_id: str) -> int:
              """Invalidate all sessions for a user. Returns count invalidated."""
        count = 0
        with self._lock:
                      for session in self._sessions.values():
                                        if session.user_id == user_id and session.is_valid:
                                                              session.is_valid = False
                                                              count += 1
                                                  return count

    def _sweep_expired(self) -> None:
              """Remove expired sessions from the store."""
        with self._lock:
                      expired_ids = [
                                        sid for sid, s in self._sessions.items()
                                        if s.is_expired() or not s.is_valid
                      ]
            for sid in expired_ids:
                              del self._sessions[sid]

    def _start_sweep_thread(self) -> None:
              """Start a background thread to periodically sweep expired sessions."""
        def sweep_loop():
                      while True:
                                        time.sleep(60)
                try:
                                      self._sweep_expired()
except Exception:
                    pass
        t = threading.Thread(target=sweep_loop, daemon=True, name="session-sweeper")
        t.start()

    @property
    def active_session_count(self) -> int:
              with self._lock:
                            return sum(1 for s in self._sessions.values() if s.is_valid and not s.is_expired())
