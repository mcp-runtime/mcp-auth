"""Reusable OAuth helpers for Python MCP resource servers."""

from .boundaries import DownstreamToken, MCPClientToken, ResourceServerCredential
from .challenge import (
    BearerAuthResult,
    ProtectedResourceChallenge,
    authorize_bearer,
    parse_www_authenticate,
    unauthorized_headers,
    unauthorized_headers_for_error,
)
from .discovery import discover_authorization_server, discover_protected_resource
from .fastmcp import RemoteAuthProvider
from .http import AsyncHTTPClient
from .integration import (
    ExchangedToken,
    TokenExchangeError,
    build_exchange_client,
    build_remote_auth,
    public_base_url,
)
from .metadata import protected_resource_metadata, required_scopes
from .models import AuthorizationServerConfig, ProtectedResourceConfig
from .oauth import OAuthState, authorization_url
from .token_exchange import (
    ExchangeError,
    PrivateKeyJWTClientAuth,
    TokenExchangeClient,
    TokenSet,
)
from .verifier import InsufficientScopeError, JWTVerifier, TokenClaims, TokenVerificationError

__all__ = [
    "ExchangeError",
    "AuthorizationServerConfig",
    "AsyncHTTPClient",
    "BearerAuthResult",
    "DownstreamToken",
    "ExchangedToken",
    "InsufficientScopeError",
    "JWTVerifier",
    "MCPClientToken",
    "OAuthState",
    "PrivateKeyJWTClientAuth",
    "ProtectedResourceChallenge",
    "ProtectedResourceConfig",
    "RemoteAuthProvider",
    "ResourceServerCredential",
    "TokenClaims",
    "TokenExchangeClient",
    "TokenExchangeError",
    "TokenSet",
    "TokenVerificationError",
    "discover_authorization_server",
    "discover_protected_resource",
    "protected_resource_metadata",
    "required_scopes",
    "parse_www_authenticate",
    "authorization_url",
    "authorize_bearer",
    "build_exchange_client",
    "build_remote_auth",
    "public_base_url",
    "unauthorized_headers",
    "unauthorized_headers_for_error",
]
