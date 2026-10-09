"""Built-in sign-in: local accounts, sessions, API tokens, roles and (optionally) single sign-on."""

from .passwords import hash_password, validate_password, verify_password
from .policy import ROLES, authorize, required_role, role_allows
from .service import (
    SESSION_COOKIE,
    AuthError,
    AuthService,
    CurrentPrincipal,
    Principal,
    bearer_token,
    get_principal,
)

__all__ = [
    "ROLES", "SESSION_COOKIE", "AuthError", "AuthService", "CurrentPrincipal", "Principal", "authorize", "bearer_token",
    "get_principal", "hash_password", "required_role", "role_allows", "validate_password", "verify_password",
]
