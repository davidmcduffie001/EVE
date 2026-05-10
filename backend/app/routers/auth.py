"""Authentication API routes."""

from __future__ import annotations

import base64
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from html import escape
from urllib.parse import urlencode
from uuid import UUID

import httpx
from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.database import get_db_session
from app.models.base import Role, SsoConfiguration, User
from app.services.audit import AuditLogService
from app.services.auth.dependencies import (
    AuthenticatedUser,
    client_host,
    create_current_user_dependency,
    fetch_user_with_role,
)
from app.services.auth.mfa import verify_totp_code
from app.services.auth.permissions import PERMISSIONS
from app.services.auth.security import InvalidTokenError, PasswordHasher, TokenSigner
from app.services.auth.sessions import RefreshSessionService

SSO_STATE_COOKIE = "eve_sso_state"
SSO_NONCE_COOKIE = "eve_sso_nonce"
SSO_COOKIE_TTL_SECONDS = 300


class LoginRequest(BaseModel):
    """Login request body."""

    email: str
    password: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        """Normalize local-account email lookup keys."""
        return value.strip().lower()


class UserResponse(BaseModel):
    """Authenticated user details returned to browser clients."""

    id: UUID
    email: str
    display_name: str
    role: str
    permissions: list[str]


class AuthResponse(BaseModel):
    """Authentication response body."""

    user: UserResponse
    access_expires_at: datetime


class MfaVerifyRequest(BaseModel):
    """MFA login verification request body."""

    mfa_challenge_token: str
    code: str = Field(min_length=6, max_length=16)


def create_auth_router(
    settings: Settings,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> APIRouter:
    """Create the auth router with concrete runtime dependencies."""
    router = APIRouter(prefix="/auth", tags=["Authentication"])
    db_dependency = get_db_session(sessionmaker)
    db_session = Depends(db_dependency)
    password_hasher = PasswordHasher()
    token_signer = TokenSigner(settings)
    current_user = create_current_user_dependency(settings, sessionmaker)
    current_user_dependency = Depends(current_user)

    @router.post("/login", response_model=None)
    async def login(
        request: LoginRequest,
        http_request: Request,
        response: Response,
        session: AsyncSession = db_session,
    ) -> AuthResponse | JSONResponse:
        """Authenticate local credentials and set browser session cookies."""
        user_with_role = await fetch_user_with_role(session, email=request.email)
        if user_with_role is None:
            await _record_login_failure(
                session=session,
                http_request=http_request,
                email=request.email,
                reason="unknown_user",
            )
            raise _invalid_credentials()

        user, role = user_with_role
        if user.disabled_at is not None:
            await _record_login_failure(
                session=session,
                http_request=http_request,
                email=request.email,
                reason="disabled_user",
                user_id=user.id,
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")
        if not password_hasher.verify_password(request.password, user.password_hash):
            await _record_login_failure(
                session=session,
                http_request=http_request,
                email=request.email,
                reason="invalid_password",
                user_id=user.id,
            )
            raise _invalid_credentials()

        if user.mfa_enrolled and user.mfa_secret is not None:
            await AuditLogService(session).record(
                user_id=user.id,
                action="auth.mfa_required",
                resource_type="session",
                outcome="success",
                source_ip=client_host(http_request),
                metadata={"email": user.email},
            )
            await session.commit()
            return JSONResponse(
                status_code=status.HTTP_202_ACCEPTED,
                content={
                    "mfa_required": True,
                    "mfa_challenge_token": token_signer.create_mfa_challenge_token(user_id=user.id),
                },
            )

        return await _issue_browser_session(
            response=response,
            http_request=http_request,
            session=session,
            settings=settings,
            token_signer=token_signer,
            user=user,
            role=role,
        )

    @router.post("/mfa/verify", response_model=AuthResponse)
    async def verify_mfa_login(
        payload: MfaVerifyRequest,
        http_request: Request,
        response: Response,
        session: AsyncSession = db_session,
    ) -> AuthResponse:
        """Verify a pending MFA login challenge and issue browser session cookies."""
        try:
            claims = token_signer.verify_mfa_challenge_token(payload.mfa_challenge_token)
            user_id = UUID(claims.subject)
        except (InvalidTokenError, ValueError):
            raise _invalid_mfa_code() from None

        user_with_role = await fetch_user_with_role(session, user_id=user_id)
        if user_with_role is None:
            raise _invalid_mfa_code()
        user, role = user_with_role
        if user.disabled_at is not None or not user.mfa_enrolled or user.mfa_secret is None:
            raise _invalid_mfa_code()
        if not verify_totp_code(user.mfa_secret, payload.code):
            await AuditLogService(session).record(
                user_id=user.id,
                action="auth.mfa_verify",
                resource_type="session",
                outcome="failure",
                source_ip=client_host(http_request),
                metadata={"reason": "invalid_code"},
            )
            await session.commit()
            raise _invalid_mfa_code()

        await AuditLogService(session).record(
            user_id=user.id,
            action="auth.mfa_verify",
            resource_type="session",
            outcome="success",
            source_ip=client_host(http_request),
        )
        return await _issue_browser_session(
            response=response,
            http_request=http_request,
            session=session,
            settings=settings,
            token_signer=token_signer,
            user=user,
            role=role,
        )

    @router.get("/sso/login", response_model=None)
    async def sso_login(session: AsyncSession = db_session) -> RedirectResponse:
        """Begin browser SSO against the configured identity provider."""
        configuration = await _require_enabled_sso(session)
        if configuration.provider == "saml":
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="SAML login initiation is not implemented yet",
            )

        if not configuration.client_id.strip() or not configuration.issuer_url.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OIDC SSO is missing issuer URL or client ID",
            )

        state_token = secrets.token_urlsafe(32)
        nonce_token = secrets.token_urlsafe(32)
        authorization_url = _oidc_authorization_url(
            settings=settings,
            configuration=configuration,
            state_token=state_token,
            nonce_token=nonce_token,
        )
        redirect = RedirectResponse(authorization_url)
        _set_cookie(
            redirect,
            settings=settings,
            name=SSO_STATE_COOKIE,
            value=state_token,
            max_age=SSO_COOKIE_TTL_SECONDS,
        )
        _set_cookie(
            redirect,
            settings=settings,
            name=SSO_NONCE_COOKIE,
            value=nonce_token,
            max_age=SSO_COOKIE_TTL_SECONDS,
        )
        return redirect

    @router.get("/sso/oidc/callback")
    async def oidc_callback(
        http_request: Request,
        response: Response,
        state: str | None = None,
        code: str | None = None,
        error: str | None = None,
        state_cookie: str | None = Cookie(default=None, alias=SSO_STATE_COOKIE),
        session: AsyncSession = db_session,
    ) -> AuthResponse:
        """Receive the OIDC authorization callback."""
        if error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="SSO identity provider rejected the login request",
            )
        if not state or not state_cookie or not hmac.compare_digest(state, state_cookie):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid SSO state")
        if not code:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing OIDC code")
        configuration = await _require_enabled_sso(session)
        if configuration.provider != "oidc":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OIDC SSO is not configured",
            )

        token_response = await _exchange_oidc_code(
            settings=settings,
            configuration=configuration,
            code=code,
        )
        userinfo = await _fetch_oidc_userinfo(
            configuration=configuration,
            token_response=token_response,
        )
        user, role = await _resolve_sso_user(
            session=session,
            configuration=configuration,
            userinfo=userinfo,
            password_hasher=password_hasher,
        )
        _clear_sso_cookies(response, settings)
        return await _issue_browser_session(
            response=response,
            http_request=http_request,
            session=session,
            settings=settings,
            token_signer=token_signer,
            user=user,
            role=role,
        )

    @router.get("/sso/saml/metadata")
    async def saml_metadata(session: AsyncSession = db_session) -> Response:
        """Return service-provider metadata for SAML IdP configuration."""
        configuration = await _require_enabled_sso(session)
        if configuration.provider != "saml":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="SAML SSO is not configured",
            )

        metadata_url = _api_url(settings, "/auth/sso/saml/metadata")
        acs_url = _api_url(settings, "/auth/sso/saml/acs")
        xml = "\n".join(
            [
                '<?xml version="1.0" encoding="UTF-8"?>',
                (
                    '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
                    f'entityID="{_xml_attr(metadata_url)}">'
                ),
                (
                    '  <SPSSODescriptor protocolSupportEnumeration='
                    '"urn:oasis:names:tc:SAML:2.0:protocol">'
                ),
                (
                    '    <AssertionConsumerService '
                    'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
                    f'Location="{_xml_attr(acs_url)}" index="0" isDefault="true" />'
                ),
                "  </SPSSODescriptor>",
                "</EntityDescriptor>",
                "",
            ]
        )
        return Response(content=xml, media_type="application/samlmetadata+xml")

    @router.post("/sso/saml/acs")
    async def saml_acs() -> None:
        """Receive SAML assertions once XML validation is implemented."""
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="SAML assertion validation is not implemented yet",
        )

    @router.post("/refresh", response_model=AuthResponse)
    async def refresh(
        http_request: Request,
        response: Response,
        refresh_token: str | None = Cookie(default=None, alias=settings.refresh_cookie_name),
        csrf_cookie: str | None = Cookie(default=None, alias=settings.csrf_cookie_name),
        csrf_header: str | None = Header(default=None, alias=settings.csrf_header_name),
        session: AsyncSession = db_session,
    ) -> AuthResponse:
        """Rotate a valid refresh session and issue fresh browser cookies."""
        _validate_csrf(csrf_cookie=csrf_cookie, csrf_header=csrf_header)
        if refresh_token is None:
            raise _refresh_required()

        refresh_service = RefreshSessionService(session)
        active_session = await refresh_service.get_active_session(refresh_token)
        if active_session is None:
            await AuditLogService(session).record(
                action="auth.refresh",
                resource_type="session",
                outcome="failure",
                source_ip=client_host(http_request),
                metadata={"reason": "expired_or_revoked"},
            )
            await session.commit()
            raise _refresh_required()

        user_with_role = await fetch_user_with_role(session, user_id=active_session.user_id)
        if user_with_role is None:
            await refresh_service.revoke_session(refresh_token)
            await AuditLogService(session).record(
                action="auth.refresh",
                resource_type="session",
                outcome="failure",
                source_ip=client_host(http_request),
                metadata={"reason": "user_missing"},
            )
            await session.commit()
            raise _refresh_required()

        await refresh_service.revoke_session(refresh_token)
        user, role = user_with_role
        return await _issue_browser_session(
            response=response,
            http_request=http_request,
            session=session,
            settings=settings,
            token_signer=token_signer,
            user=user,
            role=role,
        )

    @router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
    async def logout(
        http_request: Request,
        response: Response,
        refresh_token: str | None = Cookie(default=None, alias=settings.refresh_cookie_name),
        csrf_cookie: str | None = Cookie(default=None, alias=settings.csrf_cookie_name),
        csrf_header: str | None = Header(default=None, alias=settings.csrf_header_name),
        session: AsyncSession = db_session,
    ) -> Response:
        """Revoke the active refresh session and clear browser cookies."""
        _validate_csrf(csrf_cookie=csrf_cookie, csrf_header=csrf_header)
        if refresh_token is not None:
            refresh_service = RefreshSessionService(session)
            active_session = await refresh_service.get_active_session(refresh_token)
            await refresh_service.revoke_session(refresh_token)
            await AuditLogService(session).record(
                user_id=active_session.user_id if active_session is not None else None,
                action="auth.logout",
                resource_type="session",
                outcome="success",
                source_ip=client_host(http_request),
            )
            await session.commit()

        _clear_auth_cookies(response, settings)
        response.status_code = status.HTTP_204_NO_CONTENT
        return response

    @router.get("/me", response_model=UserResponse)
    async def me(user: AuthenticatedUser = current_user_dependency) -> UserResponse:
        """Return the current authenticated user."""
        return _serialize_user(user)

    return router


async def _issue_browser_session(
    *,
    response: Response,
    http_request: Request,
    session: AsyncSession,
    settings: Settings,
    token_signer: TokenSigner,
    user: User,
    role: Role,
) -> AuthResponse:
    access_token = token_signer.create_access_token(user_id=user.id, role_name=role.name)
    access_expires_at = datetime.now(UTC) + timedelta(seconds=settings.access_token_ttl_seconds)
    refresh_expires_at = datetime.now(UTC) + timedelta(seconds=settings.refresh_token_ttl_seconds)
    issued_refresh = await RefreshSessionService(session).issue_session(
        user_id=user.id,
        expires_at=refresh_expires_at,
        user_agent=http_request.headers.get("user-agent"),
        source_ip=client_host(http_request),
    )
    await AuditLogService(session).record(
        user_id=user.id,
        action="auth.login",
        resource_type="session",
        outcome="success",
        source_ip=client_host(http_request),
        metadata={"email": user.email, "role": role.name},
    )
    await session.commit()

    _set_cookie(
        response,
        settings=settings,
        name=settings.access_cookie_name,
        value=access_token,
        max_age=settings.access_token_ttl_seconds,
    )
    _set_cookie(
        response,
        settings=settings,
        name=settings.refresh_cookie_name,
        value=issued_refresh.refresh_token,
        max_age=settings.refresh_token_ttl_seconds,
    )
    _set_cookie(
        response,
        settings=settings,
        name=settings.csrf_cookie_name,
        value=secrets.token_urlsafe(32),
        max_age=settings.refresh_token_ttl_seconds,
        httponly=False,
    )
    return AuthResponse(user=_serialize_user(user, role), access_expires_at=access_expires_at)


async def _record_login_failure(
    *,
    session: AsyncSession,
    http_request: Request,
    email: str,
    reason: str,
    user_id: UUID | None = None,
) -> None:
    await AuditLogService(session).record(
        user_id=user_id,
        action="auth.login",
        resource_type="session",
        outcome="failure",
        source_ip=client_host(http_request),
        metadata={"email": email, "reason": reason},
    )
    await session.commit()


def _serialize_user(user: User | AuthenticatedUser, role: Role | None = None) -> UserResponse:
    role_name = role.name if role is not None else user.role_name
    permissions = (
        sorted(PERMISSIONS)
        if role is not None and role.is_system_role and role.name == "Admin"
        else role.permissions
        if role is not None
        else sorted(user.permissions)
    )
    return UserResponse(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=role_name,
        permissions=permissions,
    )


def _set_cookie(
    response: Response,
    *,
    settings: Settings,
    name: str,
    value: str,
    max_age: int,
    httponly: bool = True,
) -> None:
    response.set_cookie(
        key=name,
        value=value,
        max_age=max_age,
        httponly=httponly,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
    )


async def _require_enabled_sso(session: AsyncSession) -> SsoConfiguration:
    configuration = await session.get(SsoConfiguration, "default")
    if configuration is None or not configuration.enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="SSO is not enabled")
    return configuration


def _oidc_authorization_url(
    *,
    settings: Settings,
    configuration: SsoConfiguration,
    state_token: str,
    nonce_token: str,
) -> str:
    issuer_url = configuration.issuer_url.strip().rstrip("/")
    query = urlencode(
        {
            "response_type": "code",
            "client_id": configuration.client_id.strip(),
            "redirect_uri": _api_url(settings, "/auth/sso/oidc/callback"),
            "scope": "openid email profile",
            "state": state_token,
            "nonce": nonce_token,
        }
    )
    return f"{issuer_url}/authorize?{query}"


async def _exchange_oidc_code(
    *,
    settings: Settings,
    configuration: SsoConfiguration,
    code: str,
) -> dict[str, object]:
    token_endpoint = _oidc_provider_endpoint(configuration, "token")
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": configuration.client_id.strip(),
        "redirect_uri": _api_url(settings, "/auth/sso/oidc/callback"),
    }
    client_secret = _decrypt_sso_secret(settings=settings, configuration=configuration)
    if client_secret is not None:
        form["client_secret"] = client_secret

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(token_endpoint, data=form)
    if response.status_code >= 400:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SSO token exchange failed",
        )
    payload = response.json()
    if not isinstance(payload, dict) or not isinstance(payload.get("access_token"), str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SSO token response is invalid",
        )
    return payload


async def _fetch_oidc_userinfo(
    *,
    configuration: SsoConfiguration,
    token_response: dict[str, object],
) -> dict[str, object]:
    access_token = token_response["access_token"]
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            _oidc_provider_endpoint(configuration, "userinfo"),
            headers={"Authorization": f"Bearer {access_token}"},
        )
    if response.status_code >= 400:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SSO userinfo lookup failed",
        )
    payload = response.json()
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SSO userinfo response is invalid",
        )
    return payload


async def _resolve_sso_user(
    *,
    session: AsyncSession,
    configuration: SsoConfiguration,
    userinfo: dict[str, object],
    password_hasher: PasswordHasher,
) -> tuple[User, Role]:
    email = _oidc_email(userinfo)
    user_with_role = await fetch_user_with_role(session, email=email)
    if user_with_role is not None:
        user, role = user_with_role
        if user.disabled_at is not None:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")
        return user, role

    if not configuration.auto_provision:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="SSO user is not provisioned",
        )

    role_result = await session.execute(select(Role).where(Role.name == configuration.default_role))
    role = role_result.scalar_one_or_none()
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Default SSO role is not configured",
        )

    display_name = str(userinfo.get("name") or userinfo.get("preferred_username") or email).strip()
    user = User(
        email=email,
        display_name=display_name,
        role_id=role.id,
        password_hash=password_hasher.hash_password(secrets.token_urlsafe(48)),
    )
    session.add(user)
    await session.flush()
    return user, role


def _oidc_email(userinfo: dict[str, object]) -> str:
    email = str(userinfo.get("email") or "").strip().lower()
    if "@" not in email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SSO userinfo response is missing email",
        )
    if userinfo.get("email_verified") is False:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SSO email is not verified",
        )
    return email


def _oidc_provider_endpoint(configuration: SsoConfiguration, endpoint: str) -> str:
    issuer_url = configuration.issuer_url.strip().rstrip("/")
    if not issuer_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OIDC SSO is missing issuer URL",
        )
    return f"{issuer_url}/{endpoint}"


def _decrypt_sso_secret(*, settings: Settings, configuration: SsoConfiguration) -> str | None:
    encrypted = configuration.encrypted_client_secret
    if not encrypted:
        return None
    if not encrypted.startswith("v1:"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SSO client secret format is unsupported",
        )
    try:
        ciphertext = base64.urlsafe_b64decode(encrypted.removeprefix("v1:").encode("ascii"))
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SSO client secret format is invalid",
        ) from exc
    key = settings.auth_secret_key.encode("utf-8")
    keystream = bytearray()
    counter = 0
    while len(keystream) < len(ciphertext):
        counter_bytes = counter.to_bytes(4, "big")
        keystream.extend(hmac.digest(key, counter_bytes, "sha256"))
        counter += 1
    plaintext = bytes(value ^ keystream[index] for index, value in enumerate(ciphertext))
    return plaintext.decode("utf-8")


def _api_url(settings: Settings, path: str) -> str:
    return f"{str(settings.api_base_url).rstrip('/')}{path}"


def _xml_attr(value: str) -> str:
    return escape(value, quote=True)


def _clear_auth_cookies(response: Response, settings: Settings) -> None:
    for cookie_name in [
        settings.access_cookie_name,
        settings.refresh_cookie_name,
        settings.csrf_cookie_name,
    ]:
        response.delete_cookie(
            key=cookie_name,
            secure=settings.cookie_secure,
            samesite=settings.cookie_samesite,
        )


def _clear_sso_cookies(response: Response, settings: Settings) -> None:
    for cookie_name in [SSO_STATE_COOKIE, SSO_NONCE_COOKIE]:
        response.delete_cookie(
            key=cookie_name,
            secure=settings.cookie_secure,
            samesite=settings.cookie_samesite,
        )


def _invalid_credentials() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password",
    )


def _invalid_mfa_code() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid MFA code",
    )


def _auth_required() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
    )


def _refresh_required() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Refresh session expired or revoked",
    )


def _validate_csrf(*, csrf_cookie: str | None, csrf_header: str | None) -> None:
    if csrf_cookie is None or csrf_header is None:
        raise _csrf_failed()
    if not hmac.compare_digest(csrf_cookie, csrf_header):
        raise _csrf_failed()


def _csrf_failed() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="CSRF validation failed",
    )
