import argparse
import asyncio
import json
import os

import httpx


async def main() -> None:
    parser = argparse.ArgumentParser(description="Onboard a fintech tenant through the local service")
    parser.add_argument("--tenant", default="studio-lumen")
    parser.add_argument("--email", default="owner@example.com")
    parser.add_argument("--project", required=True)
    args = parser.parse_args()
    service_url = os.environ.get("TENANT_SERVICE_URL", "http://127.0.0.1:8000")
    payload = {
        "tenant_id": args.tenant,
        "project_id": args.project,
        "owner_email": args.email,
        "owner_name": "Studio owner",
        "scopes": ["payments:write", "payments:read"],
    }
    async with httpx.AsyncClient(base_url=service_url, timeout=15.0) as client:
        response = await client.request(method="POST", url="/tenants", json=payload)
        response.raise_for_status()
        print(json.dumps(response.json(), indent=2))


if __name__ == "__main__":
    asyncio.run(main())
