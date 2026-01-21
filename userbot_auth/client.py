import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, Union
from .utils import guard

import aiohttp

JSONType = Union[Dict[str, Any], list, str, int, float, bool, None]


@dataclass
class UBTConfig:
    url: str
    secret: str
    token: Optional[str] = None
    api_key: Optional[str] = None
    api_key_file: str = "ubt_api_key.txt"
    strict: bool = True
    timeout_s: int = 20


class UserbotAuth:
    def __init__(
        self,
        url: str,
        secret: str,
        token: str | None = None,
        api_key: str | None = None,
        api_key_file: str = "ubt_api_key.txt",
        strict: bool = True,
        timeout_s: int = 20,
    ):
        if not url or not url.strip():
            raise ValueError("Missing url")
        if not secret or not secret.strip():
            raise ValueError("Missing secret")

        self.cfg = UBTConfig(
            url=url.rstrip("/"),
            secret=secret.strip(),
            token=token.strip() if token else None,
            api_key=api_key.strip() if api_key else None,
            api_key_file=api_key_file,
            strict=strict,
            timeout_s=timeout_s,
        )

        self._session: aiohttp.ClientSession | None = None

    async def aclose(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session and not self._session.closed:
            return self._session

        timeout = aiohttp.ClientTimeout(total=self.cfg.timeout_s)
        self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    def mask_key(self, k: str) -> str:
        if not k:
            return "none"
        return f"{k[:4]}****{k[-4:]}"

    def mask_phone(self, p: str | None) -> str | None:
        if not p:
            return None
        p = str(p)
        if len(p) <= 6:
            return "*" * len(p)
        return f"{p[:3]}***{p[-3:]}"

    def _load_api_key(self) -> Optional[str]:
        if self.cfg.api_key:
            return self.cfg.api_key

        if os.path.exists(self.cfg.api_key_file):
            try:
                with open(self.cfg.api_key_file, "r", encoding="utf-8") as f:
                    value = f.read().strip()
                return value if value else None
            except (OSError, UnicodeDecodeError):
                if self.cfg.strict:
                    raise RuntimeError("Failed to read api_key_file")
                return None
        return None

    def _save_api_key(self, key: str) -> bool:
        key = (key or "").strip()
        if not key:
            if self.cfg.strict:
                raise RuntimeError("Empty api key")
            return False

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
        msg = f"{ts}.{user_id}.{nonce}".encode("utf-8")
        return hmac.new(self.cfg.secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()

    def _hmac_headers(self, user_id: int) -> Dict[str, str]:
        ts = str(int(time.time() * 1000))
        nonce = secrets.token_hex(8)
        sign = self._sign(ts, user_id, nonce)
        return {
            "X-UBT-TS": ts,
            "X-UBT-NONCE": nonce,
            "X-UBT-SIGN": sign,
        }

    def _auth_headers(self, user_id: int, include_api_key: bool = True) -> Dict[str, str]:
        headers = self._hmac_headers(user_id)
        if include_api_key:
            api_key = self._load_api_key()
            if api_key:
                headers["X-UBT-API-KEY"] = api_key
        return headers

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, JSONType]:
        url = f"{self.cfg.url}{path}"
        session = await self._get_session()

        try:
            async with session.request(method, url, json=json_body, headers=headers, params=params) as resp:
                status = resp.status
                try:
                    data = await resp.json(content_type=None)
                    return status, data
                except Exception:
                    text = await resp.text(errors="ignore")
                    return status, {"ok": False, "error": "NON_JSON_RESPONSE", "raw": text[:2000]}
        except Exception as e:
            return 0, {"ok": False, "error": "NETWORK_ERROR", "detail": str(e)}

    async def provision(self, user_id: int) -> Dict[str, Any]:
        if not self.cfg.token:
            return {"ok": False, "error": "MISSING_PROVISION_TOKEN"}

        status, data = await self._request_json(
            "POST",
            "/api/v1/create/provision/issue-key",
            json_body={"user_id": user_id},
            headers={
                "X-UBT-SCOPE": "PROVISION",
                "X-UBT-PROVISION": self.cfg.token
            }
        )

        if status != 200 or not isinstance(data, dict) or not data.get("ok"):
            if self.cfg.strict:
                raise RuntimeError(f"UBT provision failed: {status} {data}")
            return {"ok": False, "http": status, "data": data}

        api_key = (data.get("api_key") or "").strip()
        if not api_key:
            if self.cfg.strict:
                raise RuntimeError("UBT provision response missing api_key")
            return {"ok": False, "http": status, "data": data, "error": "MISSING_API_KEY"}

        self._save_api_key(api_key)
        return {"ok": True, "http": status, "api_key_saved": True}

    async def now_install(self, user_id: int) -> Dict[str, Any]:
        existing_key = self._load_api_key()
        if existing_key:
            return {"ok": True, "installed": True, "reason": "API_KEY_PRESENT"}

        if not self.cfg.token:
            return {"ok": False, "installed": False, "reason": "MISSING_PROVISION_TOKEN"}

        result = await self.provision(user_id)

        if not result.get("ok"):
            return {"ok": False, "installed": False, "reason": "PROVISION_FAILED", "provision": result}

        return {"ok": True, "installed": True, "provision": result}

    @guard(strict=True, retries=2)
    async def check(self, user_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
        body = {**payload, "user_id": user_id}
        headers = self._auth_headers(user_id, include_api_key=True)

        status, data = await self._request_json(
            "POST",
            "/api/v1/create/check-update",
            json_body=body,
            headers=headers,
        )
        return {"http": status, "data": data}

    @guard(strict=True, retries=2)
    async def log_update(
        self,
        user_id: int,
        first_name: str | None = None,
        phone_number: str | None = None,
        system: str | None = None,
        version: str | None = None,
        **meta: Any,
    ) -> Dict[str, Any]:
        headers = self._auth_headers(user_id, include_api_key=True)
        payload = {
            "user_id": user_id,
            "first_name": first_name,
            "phone_number": phone_number,
            "system": system,
            "version": version,
            **meta,
        }

        status, data = await self._request_json(
            "POST",
            "/api/v1/create/log-update",
            json_body=payload,
            headers=headers,
        )
        return {"http": status, "data": data}

    async def health(self) -> Dict[str, Any]:
        status, data = await self._request_json("GET", "/api/v1/create/health-ubt")
        return {"http": status, "data": data}

    async def runtime_post(self, api: str, user_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
        api_key = self._load_api_key()
        if not api_key:
            raise RuntimeError("NO_CREATE_FILE_API_KEY")

        headers = {
            **self._hmac_headers(user_id),
            "X-UBT-USER-ID": str(user_id),
            "X-UBT-API-KEY": str(api_key),
            "Content-Type": "application/json",
        }

        status, data = await self._request_json(
            "POST",
            f"/api/v1/{api}",
            json_body=payload,
            headers=headers,
        )

        if status == 403 and isinstance(data, dict) and data.get("status") == "DISCONNECTED":
            raise RuntimeError("USERBOT_DISCONNECTED_BY_SERVER")

        return {"http": status, "data": data}
