# Userbot-Auth Python Client Helper (aiohttp)
# - Supports: provision issue-key, runtime authenticated requests, optional HMAC nonce signing
# - Designed for userbot environments (Pyrogram, Telethon, etc.)
#
# Requirements:
#   pip install aiohttp
#
# ENV (optional):
#   UBT_API_BASE=https://api.ryzenths.dpdns.org
#   UBT_PROVISION_TOKEN=...
#   UBT_SECRET=...   (only if you enable HMAC nonce signing from the client)

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, Union

import aiohttp

def _now_ms() -> int:
    return int(time.time() * 1000)

def mask_key(k: Optional[str]) -> Optional[str]:
    if not k:
        return None
    k = str(k)
    if len(k) <= 12:
        return "*" * len(k)
    return f"{k[:12]}********{k[-4:]}"

def mask_phone(p: Optional[str]) -> Optional[str]:
    if not p:
        return None
    p = str(p)
    if len(p) <= 6:
        return "*" * len(p)
    return f"{p[:3]}***{p[-3:]}"

@dataclass
class AuthResult:
    ok: bool
    code: int
    reason: str

class UserbotAuthError(RuntimeError):
    pass

class RateLimitError(UserbotAuthError):
    def __init__(self, code: int, data: dict):
        super().__init__(f"RATE_LIMIT: {code} {data}")
        self.code = code
        self.data = data

class UserbotAuthClient:
    """
    Minimal client helper for Userbot-Auth APIs.

    Auth modes:
    - Provision (server bootstrap): header X-UBT-PROVISION
    - Runtime auth: headers X-UBT-USER-ID + X-UBT-LIVE-API-KEY (fallback X-UBT-API-KEY)
    - Optional HMAC nonce signing (extra hardening): X-UBT-TS / X-UBT-NONCE / X-UBT-SIGN
      NOTE: Prefer server-side signing, but client-side signing is supported if you own the SECRET.
    """

    def __init__(
        self,
        base_url: str,
        user_id: Optional[int] = None,
        live_api_key: Optional[str] = None,
        legacy_api_key: Optional[str] = None,
        provision_token: Optional[str] = None,
        ubt_secret: Optional[str] = None,
        timeout: int = 10,
        user_agent: str = "UserbotAuthClient/1.0",
    ):
        self.base_url = base_url.rstrip("/")
        self.user_id = user_id
        self.live_api_key = live_api_key
        self.legacy_api_key = legacy_api_key
        self.provision_token = provision_token
        self.ubt_secret = ubt_secret  # only needed if you enable HMAC nonce signing
        self.timeout = timeout
        self.user_agent = user_agent

        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> "UserbotAuthClient":
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={"User-Agent": self.user_agent},
            )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    # ---------------------------
    # Internal helpers
    # ---------------------------
    def _require_session(self) -> aiohttp.ClientSession:
        if not self._session or self._session.closed:
            raise UserbotAuthError("ClientSession is not started. Use: async with UserbotAuthClient(...)")
        return self._session

    def _runtime_headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        if not self.user_id:
            raise UserbotAuthError("Missing user_id for runtime auth")
        api_key = self.live_api_key or self.legacy_api_key
        if not api_key:
            raise UserbotAuthError("Missing runtime API key (live_api_key or legacy_api_key)")

        h: Dict[str, str] = {
            "Content-Type": "application/json",
            "X-UBT-USER-ID": str(self.user_id),
        }
        if self.live_api_key:
            h["X-UBT-LIVE-API-KEY"] = self.live_api_key
        else:
            h["X-UBT-API-KEY"] = self.legacy_api_key

        if extra:
            h.update(extra)
        return h

    def _provision_headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        if not self.provision_token:
            raise UserbotAuthError("Missing provision_token")
        h: Dict[str, str] = {
            "Content-Type": "application/json",
            "X-UBT-PROVISION": self.provision_token,
        }
        if extra:
            h.update(extra)
        return h

    def _hmac_nonce_headers(self, user_id: int) -> Dict[str, str]:
        """
        Optional hardening header set:
          X-UBT-TS, X-UBT-NONCE, X-UBT-SIGN where sign = HMAC_SHA256(UBT_SECRET, f"{ts}.{user_id}.{nonce}")
        """
        if not self.ubt_secret:
            raise UserbotAuthError("Missing ubt_secret for HMAC nonce signing")
        ts = str(_now_ms())
        nonce = secrets.token_hex(8)
        base = f"{ts}.{user_id}.{nonce}"
        sig = hmac.new(self.ubt_secret.encode("utf-8"), base.encode("utf-8"), hashlib.sha256).hexdigest()
        return {
            "X-UBT-TS": ts,
            "X-UBT-NONCE": nonce,
            "X-UBT-SIGN": sig,
        }

    async def _request_json(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        json_body: Optional[dict] = None,
        allow_429_raise: bool = True,
    ) -> Tuple[int, dict]:
        session = self._require_session()
        url = f"{self.base_url}{path}"

        async with session.request(method, url, headers=headers, json=json_body) as resp:
            status = resp.status
            text = await resp.text()

            try:
                data = json.loads(text) if text else {}
            except json.JSONDecodeError:
                data = {"ok": False, "status": "FAILED", "error": "NON_JSON_RESPONSE", "raw": text[:500]}

            if allow_429_raise and status == 429:
                raise RateLimitError(status, data)

            return status, data

    # ---------------------------
    # Public API
    # ---------------------------
    async def provision_issue_key(self, user_id: int, rotate: bool = True) -> dict:
        """
        Provision a new runtime key (one-time display).
        Endpoint example: POST /api/create/provision/issue-key
        """
        headers = self._provision_headers()
        payload = {"user_id": user_id}
        status, data = await self._request_json("POST", "/api/create/provision/issue-key", headers, payload, True)

        if not (isinstance(data, dict) and data.get("ok")):
            raise UserbotAuthError(f"PROVISION_FAILED: {status} {data}")

        api_key = data.get("api_key")
        if isinstance(api_key, str) and api_key.startswith("ubt_live_"):
            self.user_id = user_id
            self.live_api_key = api_key

        return data

    async def check_update(
        self,
        user_id: int,
        first_name: str = "",
        phone_number: str = "",
        use_hmac_nonce_headers: bool = True,
    ) -> dict:
        """
        Example endpoint: POST /api/create/check-update
        Uses optional HMAC nonce headers (recommended for bootstrap endpoints).
        """
        extra = self._hmac_nonce_headers(user_id) if use_hmac_nonce_headers else {}
        headers = {"Content-Type": "application/json", **extra}
        payload = {
            "user_id": user_id,
            "first_name": (first_name or "")[:64],
            "phone_number": (phone_number or "")[:32],
        }
        status, data = await self._request_json("POST", "/api/create/check-update", headers, payload, True)

        if not (isinstance(data, dict) and data.get("ok")):
            raise UserbotAuthError(f"CHECK_UPDATE_FAILED: {status} {data}")

        return data

    async def log_update(
        self,
        payload: dict,
        use_hmac_nonce_headers: bool = True,
    ) -> dict:
        """
        Example endpoint: POST /api/create/log-update
        Payload typically includes:
          user_id, first_name, phone_number, version, device, system, platform, commit_hash, etc.
        """
        user_id = int(payload.get("user_id", 0))
        if user_id <= 0:
            raise UserbotAuthError("log_update payload missing user_id")

        extra = self._hmac_nonce_headers(user_id) if use_hmac_nonce_headers else {}
        headers = {"Content-Type": "application/json", **extra}
        status, data = await self._request_json("POST", "/api/create/log-update", headers, payload, True)

        if not (isinstance(data, dict) and data.get("ok")):
            raise UserbotAuthError(f"LOG_UPDATE_FAILED: {status} {data}")

        return data

    async def runtime_post(self, path: str, body: dict) -> dict:
        """
        Call a protected runtime endpoint (requires runtime key).
        Example: /api/moderator/pmpermit or /api/moderator/admin
        """
        headers = self._runtime_headers()
        status, data = await self._request_json("POST", path, headers, body, True)

        if not (isinstance(data, dict) and (data.get("ok") or data.get("success"))):
            if isinstance(data, dict) and data.get("reason") in {"DISCONNECTED", "BANNED", "UNKNOWN_USER"}:
                raise UserbotAuthError(f"RUNTIME_BLOCKED: {status} {data}")
            raise UserbotAuthError(f"RUNTIME_FAILED: {status} {data}")

        return data

    async def health(self) -> dict:
        """
        Example endpoint: GET /api/create/health-ubt
        """
        session = self._require_session()
        url = f"{self.base_url}/api/create/health-ubt"
        async with session.get(url) as resp:
            status = resp.status
            text = await resp.text()
            try:
                data = json.loads(text) if text else {}
            except json.JSONDecodeError:
                data = {"ok": False, "error": "NON_JSON_RESPONSE", "raw": text[:500]}
            if status != 200:
                raise UserbotAuthError(f"HEALTH_FAILED: {status} {data}")
            return data


# ---------------------------
# Minimal usage examples
# ---------------------------

async def _example_minimal_runtime():
    """
    Minimal runtime call example:
      - You already have ubt_live_* stored
      - Call a protected endpoint
    """
    base = "https://api.ryzenths.dpdns.org"
    user_id = 12345678
    api_key = "ubt_live_REPLACE_ME"

    async with UserbotAuthClient(base_url=base, user_id=user_id, live_api_key=api_key) as ubt:
        res = await ubt.runtime_post("/api/moderator/pmpermit", {"text": "Hello"})
        print("OK:", res)


async def _example_provision_then_runtime():
    """
    Provision a key (admin/bootstrap), then use it for runtime calls.
    """
    base = "https://api.ryzenths.dpdns.org"
    provision = "REPLACE_PROVISION_TOKEN"
    user_id = 12345678

    async with UserbotAuthClient(base_url=base, provision_token=provision) as ubt:
        issued = await ubt.provision_issue_key(user_id=user_id, rotate=True)
        print("Issued:", {**issued, "api_key": mask_key(issued.get("api_key"))})

        res = await ubt.runtime_post("/api/moderator/admin", {"text": "Test message"})
        print("Runtime OK:", res)


# Uncomment to test locally:
# asyncio.run(_example_minimal_runtime())
# asyncio.run(_example_provision_then_runtime())
