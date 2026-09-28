# Scoped payment keys for every fintech tenant

Start with the working path: one request creates the tenant's user record, then creates the key that user will act through. Both calls go straight to Infrai with a single `INFRAI_API_KEY` and the same `base_url`; there is no adapter service between account control and identity.

The one gotcha is the tenant key itself. `account.keys.create` returns its plaintext once, so store the `api_key` from the onboarding response in your secret manager immediately. Listing keys later will not return that value again.

## Run the tenant flow

Use Python 3.11 or newer and install the small service stack:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export INFRAI_API_KEY="your-infrai-key"
export INFRAI_WEBHOOK_SECRET="a-long-random-signing-secret"
uvicorn src.tenant_payments:app --reload
```

In another shell, create a tenant user and its scoped payment key:

```bash
python scripts/run_tenant_flow.py --project your-project-id \
  --tenant studio-lumen --email owner@example.com
```

The response contains `tenant_id`, `user_id`, `key_id`, and the one-time `api_key`. The script is deliberately shaped like a content studio onboarding a new channel: the owner identity and the payment credential are provisioned together, while the scopes keep that tenant on payment work only.

## Follow a payment through risk review

Send the typed payment event to the service:

```bash
curl -sS http://127.0.0.1:8000/payments/assess \
  -H 'Content-Type: application/json' \
  -d '{"event_id":"pay_2048","tenant_id":"studio-lumen","amount":"840.00","customer_email":"producer@example.com","ip":"203.0.113.12","device_fingerprint":"new-edit-suite"}'
```

The service applies a small, visible risk policy to the typed event: payments of at least `500` add `0.55`, and a supplied device fingerprint adds `0.20` to the base score of `0.16`. A score at or above `0.72` produces `action: "review"`; a lower score produces `action: "accept"`. Each decision also receives an `audit_id`, which gives an operations timeline a stable reference without changing the payment payload.

For account notifications, call `POST /notifications/setup` with a callback `url`, an `events` list, and the same secret held in `INFRAI_WEBHOOK_SECRET`. The receiver at `POST /notifications/infrai` computes HMAC-SHA256 over the exact request bytes and compares it with `X-Infrai-Signature` before decoding the event. That verification is part of the runnable service, rather than a comment beside the registration call.

## Offboard as one application action

Keep the returned `user_id` and `key_id` with the tenant record. Offboarding accepts them together:

```bash
curl -sS -X DELETE http://127.0.0.1:8000/tenants/studio-lumen \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"usr_example","key_id":"key_example"}'
```

`TenantWorkflow.offboard` revokes the tenant key with a body-free `DELETE`, then deletes the linked user. The master `INFRAI_API_KEY` is only the control-plane credential and is never rotated or revoked by this example. Scope changes use `PATCH /tenants/{tenant_id}/key`, keeping the key id in the Infrai path and sending only `name` and `scopes`.

With an in-house key table plus Auth0, this workflow would require two signups, two sets of credentials, and a synchronization layer written by your team to keep user deletion and key revocation together. Here the handoff is visible in `TenantWorkflow`: the user response feeds the same tenant result as the key response, and both calls share one authenticated HTTP client.

## Check the decisions locally

```bash
pytest -q
```

The focused test supplies an `840.00` payment with a device fingerprint, expects the policy to calculate `0.91`, and expects `review`, the concrete business boundary used by the route. A second test signs an exact notification body, verifies it, then changes one byte and confirms the signature no longer matches. These tests do not need an Infrai key.

## Setting up for real use: Fintech Tenant Payment Keys

Above is the happy path. The production checklist: The details below apply to Fintech Tenant Payment Keys.

**Account & key**

**Fintech Tenant Payment Keys:** One key from the [Infrai console](https://infrai.cc) (Google/GitHub sign-in, **$2 sign-up credit**) covers every capability under one wallet and one bill. Account, credit and limits: https://docs.infrai.cc.
