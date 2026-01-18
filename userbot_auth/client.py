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
      v = open(self.cfg.api_key_file, "r", encoding="utf-8").read().strip()
      return v or None
    return None

  def _save_api_key(self, key: str) -> None:
    self.cfg.api_key = key
    with open(self.cfg.api_key_file, "w", encoding="utf-8") as f:
      f.write(key)

  def _sign(self, ts: str, user_id: int, nonce: str) -> str:
    msg = f"{ts}.{user_id}.{nonce}".encode("utf-8")
    return hmac.new(self.cfg.secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()

  def _headers(self, user_id: int) -> Dict[str, str]:
    ts = str(int(time.time()))
    nonce = secrets.token_hex(8)
    sign = self._sign(ts, user_id, nonce)
    h = {
      "X-UBT-TS": ts,
      "X-UBT-NONCE": nonce,
      "X-UBT-SIGN": sign,
    }
    k = self._load_api_key()
    if k:
      h["X-UBT-KEY"] = k
    return h

  async def _post(self, path: str, json: Dict[str, Any], headers: Dict[str, str] | None = None):
    url = f"{self.cfg.url}{path}"
    async with aiohttp.ClientSession() as s:
      async with s.post(url, json=json, headers=headers) as r:
        data = await r.json(content_type=None)
        return r.status, data

  async def _get(self, path: str, json: Dict[str, Any], headers: Dict[str, str] | None = None):
    url = f"{self.cfg.url}{path}"
    async with aiohttp.ClientSession() as s:
      async with s.get(url, json=json, headers=headers) as r:
        data = await r.json(content_type=None)
        return r.status, data

  async def now_install(self, user_id: int) -> Dict[str, Any]:
    existing = self._load_api_key()
    if existing:
      return {"ok": True, "installed": True, "api_key": "present"}

    if not self.cfg.token:
      return {"ok": False, "installed": False, "reason": "missing_provision_token"}

    res = await self.provision(user_id)
    return {"ok": True, "installed": True, "provision": res}

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
    status, data = await self._post("/api/v1/create/check-update", json={"user_id": user_id}, headers=headers)
    return {"http": status, "data": data}

  async def health(self, user_id: int) -> Dict[str, Any]:
    status, data = await self._get("/api/v1/create/health-ubt")
    return {"http": status, "data": data}
  
  async def log_update(
    self,
    user_id: int,
    first_name: str | None = None,
    phone_number: str | None = None,
    system: str | None = None,
    version: str | None = None,
    **meta
  ):
    headers = self._headers(user_id)
    payload = {
      "user_id": user_id,
      "first_name": first_name,
      "phone_number": phone_number,
      "system": system,
      "version": version,
      **meta
    }
    status, data = await self._post("/api/v1/create/log-update", json=payload, headers=headers)
    return {"http": status, "data": data}
