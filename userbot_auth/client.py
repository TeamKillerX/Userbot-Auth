import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import aiohttp


@dataclass
class UBTConfig:
    url: str
    secret: str
    token: Optional[str] = None
    api_key: Optional[str] = None
    api_key_file: str = "ubt_api_key.txt"
    strict: bool = True


class UserbotAuth:
    def __init__(self, url: str, secret: str, token: str | None = None,
                 api_key: str | None = None, api_key_file: str = "ubt_api_key.txt",
                 strict: bool = True):
        self.cfg = UBTConfig(url=url.rstrip("/"), secret=secret, token=token,
                             api_key=api_key, api_key_file=api_key_file, strict=strict)

    def _load_api_key(self) -> Optional[str]:
        if self.cfg.api_key:
            return self.cfg.api_key

        if os.path.exists(self.cfg.api_key_file):
            try:
                with open(self.cfg.api_key_file, "r", encoding="utf-8") as f:
                    value = f.read().strip()
                return value if value else None
            except (OSError, UnicodeDecodeError):
                if getattr(self.cfg, "strict", False):
                    raise
                return None
        return None

    def _save_api_key(self, key: str) -> bool:
        self.cfg.api_key = key
        try:
            with open(self.cfg.api_key_file, "w", encoding="utf-8") as f:
                f.write(key)
        except OSError as e:
            if self.cfg.strict:
                raise RuntimeError(f"Failed to save API key: {e}")
            return False
        return True

    def _sign(self, ts: str, user_id: int, nonce: str) -> str:
        message = f"{ts}.{user_id}.{nonce}".encode("utf-8")
        signature = hmac.new(
            self.cfg.secret.encode("utf-8"),
            message,
            hashlib.sha256
        ).hexdigest()

        return signature

    def _headers(self, user_id: int) -> Dict[str, str]:
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(8)
        signature = self._sign(timestamp, user_id, nonce)
        headers = {
            "X-UBT-TS": timestamp,
            "X-UBT-NONCE": nonce,
            "X-UBT-SIGN": signature,
        }
        api_key = self._load_api_key()
        if api_key:
            headers["X-UBT-API-KEY"] = api_key

        return headers

    async def _post(self, path: str, json: Dict[str, Any],
                   headers: Dict[str, str] | None = None) -> tuple[int, Any]:
        url = f"{self.cfg.url}{path}"
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=json, headers=headers) as response:
                data = await response.json(content_type=None)
                return response.status, data

    async def _get(self, path: str, json: Dict[str, Any],
                  headers: Dict[str, str] | None = None) -> tuple[int, Any]:
        url = f"{self.cfg.url}{path}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, json=json, headers=headers) as response:
                data = await response.json(content_type=None)
                return response.status, data

    async def now_install(self, user_id: int) -> Dict[str, Any]:
        existing_key = self._load_api_key()
        if existing_key:
            return {"ok": True, "installed": True, "api_key": "present"}

        if not self.cfg.token:
            return {"ok": False, "installed": False, "reason": "missing_provision_token"}

        result = await self.provision(user_id)
        return {"ok": True, "installed": True, "provision": result}

    async def provision(self, user_id: int) -> Dict[str, Any]:
        status, data = await self._post(
            "/api/v1/create/provision/issue-key",
            json={"user_id": user_id},
            headers={"X-UBT-PROVISION": self.cfg.token}
        )

        if status != 200 or not data or not data.get("ok"):
            if self.cfg.strict:
                raise RuntimeError(f"UBT provision failed: {status} {data}")
            return {"ok": False, "status": status, "data": data}

        api_key = data.get("api_key")
        if not api_key:
            raise RuntimeError("UBT provision response missing api_key")

        self._save_api_key(api_key)
        return {"ok": True, "api_key_saved": True}

    async def check(self, user_id: int) -> Dict[str, Any]:
        headers = self._headers(user_id)
        status, data = await self._post(
            "/api/v1/create/check-update",
            json={"user_id": user_id},
            headers=headers
        )
        return {"http": status, "data": data}

    async def health(self, user_id: int) -> Dict[str, Any]:
        status, data = await self._get("/api/v1/create/health-ubt", json={})
        return {"http": status, "data": data}

    async def runtime_post(self, api: str, user_id: int, payload: dict) -> Dict[str, Any]:
        api_key = self._load_api_key()
        if not api_key:
            raise RuntimeError("NO_CREATE_FILE_API_KEY")

        headers = {
            "X-UBT-USER-ID": str(user_id),
            "X-UBT-API-KEY": str(api_key),
            "Content-Type": "application/json",
        }

        try:
            status, data = await self._post(
                f"/api/v1/{api}",
                json=payload,
                headers=headers,
            )
        except Exception as error:
            return {
                "http": 0,
                "error": "NETWORK_ERROR",
                "detail": str(error),
            }

        if status == 403 and data.get("status") == "DISCONNECTED":
            raise RuntimeError("USERBOT_DISCONNECTED_BY_SERVER")

        return {
            "http": status,
            "data": data,
        }

    async def log_update(
        self,
        user_id: int,
        first_name: str | None = None,
        phone_number: str | None = None,
        system: str | None = None,
        version: str | None = None,
        **meta: Any
    ) -> Dict[str, Any]:
        headers = self._headers(user_id)

        payload = {
            "user_id": user_id,
            "first_name": first_name,
            "phone_number": phone_number,
            "system": system,
            "version": version,
            **meta
        }
        status, data = await self._post(
            "/api/v1/create/log-update",
            json=payload,
            headers=headers
        )
        return {"http": status, "data": data}
