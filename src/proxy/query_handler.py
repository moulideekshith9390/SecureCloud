"""Query handler: parses, authorizes, encrypts, and routes database queries."""

import json
import logging
from enum import Enum
from typing import Any, Dict, Optional

from src.auth.rbac import RBACPolicy, Operation, parse_operation
from src.auth.session_manager import SessionManager
from src.crypto.aes_gcm import AESGCMCipher

logger = logging.getLogger("securecloud.query_handler")


class QueryType(Enum):
      SELECT = "SELECT"
      INSERT = "INSERT"
      UPDATE = "UPDATE"
      DELETE = "DELETE"
      AUTH = "AUTH"
      LOGOUT = "LOGOUT"


class QueryError(Exception):
      """Raised when a query cannot be processed."""
      def __init__(self, code: str, message: str):
                super().__init__(message)
                self.code = code


def _detect_operation(query_type: str) -> Optional[Operation]:
      """Map a query type string to an RBAC Operation."""
      mapping = {
          "SELECT": Operation.SELECT,
          "INSERT": Operation.INSERT,
          "UPDATE": Operation.UPDATE,
          "DELETE": Operation.DELETE,
      }
      return mapping.get(query_type.upper())


class QueryHandler:
      """Processes incoming query requests through auth, RBAC, and encryption.

          Wire protocol (JSON over TCP):
                  Request:  {"token": "...", "type": "SELECT|INSERT|...", "payload": "..."}
                          Response: {"status": "ok|error", "data": "...", "error": "..."}
                              """

    def __init__(
              self,
              cipher: AESGCMCipher,
              rbac: RBACPolicy,
              session_manager: SessionManager,
    ):
              self._cipher = cipher
              self._rbac = rbac
              self._sessions = session_manager

    async def process(self, raw_data: bytes) -> bytes:
              """Process a raw request and return a raw response."""
              try:
                            request = json.loads(raw_data.decode("utf-8"))
                            response = await self._dispatch(request)
except json.JSONDecodeError as exc:
            response = {"status": "error", "error": f"Invalid JSON: {exc}"}
except QueryError as exc:
                    response = {"status": "error", "code": exc.code, "error": str(exc)}
except Exception as exc:
            logger.exception("Unexpected error processing query")
            response = {"status": "error", "error": "Internal server error"}
        return json.dumps(response).encode("utf-8")

    async def _dispatch(self, request: Dict[str, Any]) -> Dict[str, Any]:
              qtype = request.get("type", "").upper()

        if qtype == "AUTH":
                      return await self._handle_auth(request)

        if qtype == "LOGOUT":
                      return await self._handle_logout(request)

        session = self._authenticate(request.get("token", ""))
        operation = _detect_operation(qtype)
        if operation is None:
                      raise QueryError("UNKNOWN_QUERY_TYPE", f"Unknown query type: {qtype!r}")

        if not self._rbac.is_allowed(session.role, operation):
                      raise QueryError(
                                        "FORBIDDEN",
                                        f"Role {session.role.value!r} is not allowed to perform {qtype}",
                      )

        payload = request.get("payload", "")
        encrypted = self._cipher.encrypt(
                      payload.encode("utf-8"),
                      aad=session.session_id.encode("utf-8"),
        )
        logger.info(
                      "user=%s role=%s op=%s payload_len=%d",
                      session.user_id, session.role.value, qtype, len(payload),
        )
        return {
                      "status": "ok",
                      "encrypted_payload": encrypted.hex(),
                      "session_id": session.session_id,
        }

    def _authenticate(self, token: str):
              session = self._sessions.validate_token(token)
              if session is None:
                            raise QueryError("UNAUTHORIZED", "Invalid or expired session token")
                        return session

    async def _handle_auth(self, request: Dict[str, Any]) -> Dict[str, Any]:
              user_id = request.get("user_id")
        role_str = request.get("role", "readonly")
        if not user_id:
                      raise QueryError("BAD_REQUEST", "user_id is required for AUTH")
                  from src.auth.rbac import parse_role
        role = parse_role(role_str)
        token = self._sessions.create_session(user_id=user_id, role=role)
        logger.info("Session created for user=%s role=%s", user_id, role.value)
        return {"status": "ok", "token": token}

    async def _handle_logout(self, request: Dict[str, Any]) -> Dict[str, Any]:
              session = self._authenticate(request.get("token", ""))
        self._sessions.invalidate(session.session_id)
        logger.info("Session invalidated for user=%s", session.user_id)
        return {"status": "ok", "message": "Logged out successfully"}
