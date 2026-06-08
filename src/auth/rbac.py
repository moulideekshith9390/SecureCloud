"""Role-Based Access Control (RBAC) module for SecureCloud Database Proxy."""

from enum import Enum, auto
from typing import Dict, Set, Optional


class Operation(Enum):
        SELECT = auto()
      INSERT = auto()
      UPDATE = auto()
      DELETE = auto()
      ADMIN = auto()


  class Role(Enum):
          ADMIN = "admin"
        READ_WRITE = "readwrite"
        READ_ONLY = "readonly"
        AUDITOR = "auditor"


    # Default permission matrix: Role -> allowed operations
    ROLE_PERMISSIONS: Dict[Role, Set[Operation]] = {
          Role.ADMIN: {
                    Operation.SELECT,
                    Operation.INSERT,
                    Operation.UPDATE,
                    Operation.DELETE,
                    Operation.ADMIN,
          },
          Role.READ_WRITE: {
                    Operation.SELECT,
                    Operation.INSERT,
                    Operation.UPDATE,
          },
          Role.READ_ONLY: {
                    Operation.SELECT,
          },
          Role.AUDITOR: {
                    Operation.SELECT,
          },
    }


    class RBACPolicy:
          """Manages role-based access control policies for database operations.

              Permissions are evaluated at query parse time, before any encryption,
                  to prevent privilege escalation through crafted ciphertext.
                      """

          def __init__(self, custom_permissions: Optional[Dict[Role, Set[Operation]]] = None):
                      self._permissions = custom_permissions or dict(ROLE_PERMISSIONS)

                def is_allowed(self, role: Role, operation: Operation, namespace: str = "*") -> bool:
                          """Return True if the given role may perform the operation."""
                          allowed_ops = self._permissions.get(role, set())
                          return operation in allowed_ops

                      def grant(self, role: Role, operation: Operation) -> None:
                                """Grant an additional operation to a role."""
                                self._permissions.setdefault(role, set()).add(operation)

                            def revoke(self, role: Role, operation: Operation) -> None:
                                      """Revoke an operation from a role."""
                                      self._permissions.get(role, set()).discard(operation)

                                  def get_allowed_operations(self, role: Role) -> Set[Operation]:
                                              """Return the set of operations allowed for a role."""
                                            return frozenset(self._permissions.get(role, set()))


                                    def parse_role(role_str: str) -> Role:
                                          """Parse a role string into a Role enum value."""
                                          try:
                                              return Role(role_str.lower())
                                          except ValueError:
                                              raise ValueError(f"Unknown role: {role_str!r}. Valid roles: {[r.value for r in Role]}")


                                      def parse_operation(op_str: str) -> Operation:
                                            """Parse an operation string into an Operation enum value."""
                                            try:
                                                return Operation[op_str.upper()]
                                            except KeyError:
                                                raise ValueError(f"Unknown operation: {op_str!r}. Valid ops: {[o.name for o in Operation]}")
