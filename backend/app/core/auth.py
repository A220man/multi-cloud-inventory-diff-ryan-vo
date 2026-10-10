"""Authentication and Authorization dependencies supporting OIDC Bearer tokens and local Demo mode."""
from collections.abc import Callable
from datetime import datetime, timezone, timedelta
from typing import Any, Optional
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt, JWTError
import httpx
from app.core.config import settings

DEMO_JWT_SECRET = "cloud-inventory-demo-local-secret-do-not-use-in-prod"
ALGORITHM = "HS256"

security = HTTPBearer(auto_error=False)

# In-memory cache for OIDC JWKS
_jwks_cache: Optional[dict[str, Any]] = None
_jwks_fetched_at: Optional[datetime] = None


class AuthUser:
    def __init__(self, username: str, roles: list[str], claims: dict[str, Any]):
        self.username = username
        self.roles = roles
        self.claims = claims

    def has_role(self, required_role: str) -> bool:
        hierarchy = {
            "viewer": ["viewer", "operator", "admin"],
            "operator": ["operator", "admin"],
            "admin": ["admin"],
        }
        allowed_roles = hierarchy.get(required_role, [required_role])
        return any(r in allowed_roles for r in self.roles)


def create_demo_token(username: str, role: str, expires_delta: Optional[timedelta] = None) -> str:
    """Generate a signed demo token for local testing."""
    if not settings.DEMO_MODE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Demo token issuance is disabled outside of explicit DEMO_MODE."
        )

    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(hours=8))
    to_encode = {
        "sub": username,
        "preferred_username": username,
        "iss": "demo-authority",
        "aud": settings.OIDC_AUDIENCE,
        "exp": expire,
        "realm_access": {"roles": [role]},
        "resource_access": {
            settings.OIDC_CLIENT_ID: {"roles": [role]}
        }
    }
    return jwt.encode(to_encode, DEMO_JWT_SECRET, algorithm=ALGORITHM)


def fetch_oidc_jwks() -> dict[str, Any]:
    """Fetch OIDC JWKS keys from Keycloak endpoint."""
    global _jwks_cache, _jwks_fetched_at
    now = datetime.now(timezone.utc)
    if _jwks_cache and _jwks_fetched_at and (now - _jwks_fetched_at).total_seconds() < 3600:
        return _jwks_cache

    if not settings.OIDC_JWKS_URI:
        return {}

    try:
        response = httpx.get(settings.OIDC_JWKS_URI, timeout=5.0)
        if response.status_code == 200:
            _jwks_cache = response.json()
            _jwks_fetched_at = now
            return _jwks_cache
    except Exception:
        pass
    return _jwks_cache or {}


def extract_roles(payload: dict[str, Any]) -> list[str]:
    """Extract standard roles from token payload."""
    roles = []
    # Realm roles
    realm_access = payload.get("realm_access", {})
    if isinstance(realm_access, dict):
        roles.extend(realm_access.get("roles", []))

    # Resource client roles
    resource_access = payload.get("resource_access", {})
    if isinstance(resource_access, dict):
        client_access = resource_access.get(settings.OIDC_CLIENT_ID, {})
        if isinstance(client_access, dict):
            roles.extend(client_access.get("roles", []))

    # Fallback to direct role attribute
    direct_roles = payload.get("roles", [])
    if isinstance(direct_roles, list):
        roles.extend(direct_roles)

    return list(set(roles))


async def get_current_user(
    auth: Optional[HTTPAuthorizationCredentials] = Security(security)
) -> AuthUser:
    """Validate Bearer token from authorization header."""
    if not auth or not auth.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header. Expected Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth.credentials

    # If demo mode is explicitly enabled, first try decoding with demo secret
    if settings.DEMO_MODE:
        try:
            payload = jwt.decode(
                token,
                DEMO_JWT_SECRET,
                algorithms=[ALGORITHM],
                audience=settings.OIDC_AUDIENCE,
            )
            username = payload.get("preferred_username") or payload.get("sub") or "demo-user"
            roles = extract_roles(payload)
            return AuthUser(username=username, roles=roles, claims=payload)
        except JWTError:
            pass  # Fall through to OIDC key validation

    # Validate against standard OIDC Keycloak JWKS
    jwks = fetch_oidc_jwks()
    try:
        header = jwt.get_unverified_header(token)
        rsa_key = {}
        for key in jwks.get("keys", []):
            if key.get("kid") == header.get("kid"):
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key.get("use", "sig"),
                    "n": key["n"],
                    "e": key["e"],
                }
                break

        if rsa_key:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=["RS256"],
                audience=settings.OIDC_AUDIENCE,
                issuer=settings.OIDC_ISSUER_URL,
            )
            username = payload.get("preferred_username") or payload.get("sub") or "user"
            roles = extract_roles(payload)
            return AuthUser(username=username, roles=roles, claims=payload)
    except Exception:
        pass

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token: verification failed or token expired.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_role(role: str) -> Callable:
    """Dependency factory checking user has at least the required role."""
    async def role_checker(user: AuthUser = Depends(get_current_user)) -> AuthUser:
        if not user.has_role(role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: role '{role}' or higher is required. User has roles: {user.roles}",
            )
        return user
    return role_checker
