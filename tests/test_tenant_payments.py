import asyncio
import hashlib
import hmac
import json

from src.tenant_payments import (
    PaymentAction,
    PaymentEvent,
    TenantWorkflow,
    verify_notification_signature,
)


def test_high_risk_payment_is_held_for_review() -> None:
    workflow = TenantWorkflow(object())  # type: ignore[arg-type]
    event = PaymentEvent(
        event_id="pay_2048",
        tenant_id="studio-lumen",
        amount="840.00",
        customer_email="producer@example.com",
        ip="203.0.113.12",
        device_fingerprint="new-edit-suite",
    )

    decision = asyncio.run(workflow.assess_payment(event))

    assert decision.action is PaymentAction.REVIEW
    assert decision.risk_score == 0.91
    assert decision.event_id == "pay_2048"
    assert decision.audit_id


def test_notification_signature_covers_the_exact_payload() -> None:
    secret = "local-signing-secret"
    body = json.dumps({"event": "account.keys.revoked", "tenant_id": "studio-lumen"}).encode()
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    assert verify_notification_signature(body, f"sha256={signature}", secret)
    assert not verify_notification_signature(body + b" ", f"sha256={signature}", secret)
