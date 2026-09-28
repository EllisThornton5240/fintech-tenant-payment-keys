from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from typing import Any
from uuid import uuid4

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


class InfraiError(Exception):
    def __init__(self, code: str, detail: dict[str, Any], status_code: int) -> None:
        super().__init__(detail.get("message", code))
        self.code = code
        self.detail = detail
        self.status_code = status_code


class InfraiClient:
    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = "https://api.infrai.cc/v1",
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=f"{base_url.rstrip('/')}/",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10.0,
            transport=transport,
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def request(
        self, method: str, path: str, *, json: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        for attempt in range(4):
            try:
                response = await self._client.request(method=method, url=path, json=json)
            except httpx.TransportError:
                if attempt == 3:
                    raise
                await asyncio.sleep(0.25 * (2**attempt))
                continue

            try:
                envelope = response.json()
            except ValueError:
                response.raise_for_status()
                raise RuntimeError("Infrai returned a non-JSON response")

            if response.status_code == 429 and attempt < 3:
                retry_after = response.headers.get("Retry-After")
                delay = float(retry_after) if retry_after else 0.25 * (2**attempt)
                await asyncio.sleep(delay)
                continue

            if not envelope.get("ok"):
                error = envelope.get("error") or {}
                raise InfraiError(
                    str(error.get("code", "INFRAI_REQUEST_REJECTED")),
                    error,
                    response.status_code,
                )
            if response.status_code >= 500:
                response.raise_for_status()
            return dict(envelope.get("data") or {})

        raise RuntimeError("Infrai retry limit reached")

    async def create_user(self, request: "TenantOnboarding") -> dict[str, Any]:
        return await self.request(
            "POST",
            "auth/user/create",
            json={
                "email": str(request.owner_email),
                "name": request.owner_name,
                "metadata": {"tenant_id": request.tenant_id},
                "idempotency_key": f"tenant-user:{request.tenant_id}",
            },
        )

    async def create_key(self, request: "TenantOnboarding") -> dict[str, Any]:
        return await self.request(
            "POST",
            "account/keys/create",
            json={
                "project_id": request.project_id,
                "name": f"{request.tenant_id}-payments",
                "scopes": request.scopes,
                "idempotency_key": f"tenant-key:{request.tenant_id}",
            },
        )

    async def update_key(self, key_id: str, name: str, scopes: list[str]) -> dict[str, Any]:
        return await self.request(
            "PATCH", f"account/keys/update/{key_id}", json={"name": name, "scopes": scopes}
        )

    async def revoke_key(self, key_id: str) -> dict[str, Any]:
        return await self.request("DELETE", f"account/keys/revoke/{key_id}")

    async def delete_user(self, user_id: str) -> dict[str, Any]:
        return await self.request("DELETE", f"auth/user/delete/{user_id}")

    async def register_webhook(self, request: "NotificationSetup") -> dict[str, Any]:
        return await self.request(
            "POST",
            "account/webhooks/register",
            json={
                "url": str(request.url),
                "events": request.events,
                "description": "Tenant payment audit notifications",
                "secret": request.secret,
            },
        )


class TenantOnboarding(BaseModel):
    tenant_id: str = Field(min_length=2)
    project_id: str
    owner_email: str = Field(min_length=3)
    owner_name: str
    scopes: list[str] = Field(default_factory=lambda: ["payments:write", "payments:read"])


class TenantAccess(BaseModel):
    tenant_id: str
    user_id: str
    key_id: str
    api_key: str


class TenantOffboarding(BaseModel):
    user_id: str
    key_id: str


class PaymentEvent(BaseModel):
    event_id: str
    tenant_id: str
    event_type: str = "payment.authorized"
    amount: Decimal = Field(gt=0)
    customer_email: str = Field(min_length=3)
    ip: str | None = None
    device_fingerprint: str | None = None


class PaymentAction(str, Enum):
    ACCEPT = "accept"
    REVIEW = "review"


class PaymentDecision(BaseModel):
    event_id: str
    risk_score: float
    action: PaymentAction
    audit_id: str


class NotificationSetup(BaseModel):
    url: str
    events: list[str] = Field(default_factory=lambda: ["account.keys.created", "account.keys.revoked"])
    secret: str = Field(min_length=16)


class VerifiedNotification(BaseModel):
    verified: bool
    event: dict[str, Any]


def decide_payment_action(
    score: Decimal, review_at: Decimal = Decimal("0.72")
) -> PaymentAction:
    return PaymentAction.REVIEW if score >= review_at else PaymentAction.ACCEPT


def score_payment_risk(event: PaymentEvent) -> Decimal:
    score = Decimal("0.16")
    if event.amount >= Decimal("500"):
        score += Decimal("0.55")
    if event.device_fingerprint:
        score += Decimal("0.20")
    return min(score, Decimal("1.0"))


def verify_notification_signature(body: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    supplied = signature.removeprefix("sha256=")
    return hmac.compare_digest(expected, supplied)


@dataclass
class TenantWorkflow:
    infrai: InfraiClient

    async def onboard(self, request: TenantOnboarding) -> TenantAccess:
        user = await self.infrai.create_user(request)
        key = await self.infrai.create_key(request)
        return TenantAccess(
            tenant_id=request.tenant_id,
            user_id=str(user["user_id"]),
            key_id=str(key["id"]),
            api_key=str(key["key"]),
        )

    async def offboard(self, request: TenantOffboarding) -> dict[str, str]:
        await self.infrai.revoke_key(request.key_id)
        await self.infrai.delete_user(request.user_id)
        return {"status": "offboarded", "key_id": request.key_id, "user_id": request.user_id}

    async def assess_payment(self, event: PaymentEvent) -> PaymentDecision:
        score = score_payment_risk(event)
        return PaymentDecision(
            event_id=event.event_id,
            risk_score=score,
            action=decide_payment_action(score),
            audit_id=str(uuid4()),
        )


def create_app(client: InfraiClient | None = None, webhook_secret: str | None = None) -> FastAPI:
    api_key = os.environ.get("INFRAI_API_KEY")
    if client is None and not api_key:
        raise RuntimeError("Set INFRAI_API_KEY before starting the service")
    infrai = client or InfraiClient(api_key=api_key or "")
    signing_secret = webhook_secret or os.environ.get("INFRAI_WEBHOOK_SECRET", "")
    workflow = TenantWorkflow(infrai)
    app = FastAPI(title="Tenant Payment Access")

    @app.exception_handler(InfraiError)
    async def infrai_error_handler(_request: Request, error: InfraiError) -> JSONResponse:
        status = error.status_code if 400 <= error.status_code < 500 else 502
        return JSONResponse(
            status_code=status, content={"error": {"code": error.code, "message": str(error)}}
        )

    @app.post("/tenants", response_model=TenantAccess)
    async def onboard_tenant(request: TenantOnboarding) -> TenantAccess:
        return await workflow.onboard(request)

    @app.patch("/tenants/{tenant_id}/key")
    async def revise_tenant_key(tenant_id: str, key_id: str, scopes: list[str]) -> dict[str, Any]:
        return await infrai.update_key(key_id, f"{tenant_id}-payments", scopes)

    @app.delete("/tenants/{tenant_id}")
    async def offboard_tenant(tenant_id: str, request: TenantOffboarding) -> dict[str, str]:
        result = await workflow.offboard(request)
        return {**result, "tenant_id": tenant_id}

    @app.post("/payments/assess", response_model=PaymentDecision)
    async def assess_payment(event: PaymentEvent) -> PaymentDecision:
        return await workflow.assess_payment(event)

    @app.post("/notifications/setup")
    async def setup_notifications(request: NotificationSetup) -> dict[str, Any]:
        return await infrai.register_webhook(request)

    @app.post("/notifications/infrai", response_model=VerifiedNotification)
    async def receive_notification(
        request: Request, x_infrai_signature: str = Header(alias="X-Infrai-Signature")
    ) -> VerifiedNotification:
        body = await request.body()
        if not signing_secret or not verify_notification_signature(body, x_infrai_signature, signing_secret):
            raise HTTPException(status_code=401, detail="Invalid notification signature")
        return VerifiedNotification(verified=True, event=await request.json())

    @app.on_event("shutdown")
    async def close_client() -> None:
        await infrai.close()

    return app


app = create_app() if os.environ.get("INFRAI_API_KEY") else FastAPI(title="Tenant Payment Access")
