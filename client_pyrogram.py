# Code by Rendy Projects
# Aura elite programmer
# NEW: https://ubt.ryzenths.dpdns.org/api/v1 (opsional)

import asyncio
import hashlib
import hmac
import logging
import os
import secrets
import time

import aiohttp
from pyrogram import Client

API_ID = 0
API_HASH = ""
SESSION_STRING = ""
UBT_SECRET = ""
UBT_PROVISION_TOKEN = ""
API_ENDPOINT_URL = "https://api.ryzenths.dpdns.org/"
API_KEY_FILE = "ubt_api_key.txt"

def load_api_key():
    if os.path.exists(API_KEY_FILE):
        k = open(API_KEY_FILE, "r", encoding="utf-8").read().strip()
        return k or None
    return None

def mask_key(k: str) -> str:
    if not k:
        return "none"
    return f"{k[:4]}****{k[-4:]}"

def mask_phone(p: str | None) -> str | None:
    if not p:
        return None
    p = str(p)
    if len(p) <= 6:
        return "*" * len(p)
    return f"{p[:3]}***{p[-3:]}"

def save_api_key(k: str):
    with open(API_KEY_FILE, "w", encoding="utf-8") as f:
        f.write(k)

async def ensure_connected_api_key(user_id: int) -> str:
    k = load_api_key()
    if k:
        return k

    provision_token = UBT_PROVISION_TOKEN
    if not provision_token:
        raise RuntimeError("Missing UBT_PROVISION_TOKEN")

    async with aiohttp.ClientSession() as s:
        r = await s.post(
            f"{API_ENDPOINT_URL}/api/create/provision/issue-key",
            json={"user_id": user_id},
            headers={"X-UBT-PROVISION": provision_token},
            timeout=15
        )
        data = await r.json()

    if not (isinstance(data, dict) and data.get("ok") and data.get("api_key")):
        raise RuntimeError(f"PROVISION_FAILED: {data}")

    save_api_key(data["api_key"])
    return data["api_key"]

def sign_body(ts: str, user_id: int, first_name: str = "", phone_number: str = "") -> str:
    base = f"{ts}.{user_id}.{first_name}.{phone_number}"
    return hmac.new(UBT_SECRET.encode(), base.encode(), hashlib.sha256).hexdigest()

def sign_nonce(ts: str, user_id: int, nonce: str) -> str:
    base = f"{ts}.{user_id}.{nonce}"
    return hmac.new(UBT_SECRET.encode(), base.encode(), hashlib.sha256).hexdigest()

class UBTApi:
    def __init__(self, base_url: str = API_ENDPOINT_URL):
        self.base_url = base_url.rstrip("/")
        self.session: aiohttp.ClientSession | None = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15)
        )
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()

    async def create_check_ping(self, user_id: int, first_name: str = "", phone_number: str = ""):
        assert self.session is not None

        ts = str(int(time.time() * 1000))
        nonce = secrets.token_hex(8)

        payload = {
            "user_id": user_id,
            "first_name": first_name,
            "phone_number": phone_number,
        }

        headers = {
            "X-UBT-TS": ts,
            "X-UBT-NONCE": nonce,
            "X-UBT-SIGN": sign_nonce(ts, user_id, nonce),
        }

        async with self.session.post(
            f"{self.base_url}/api/create/check-update",
            json=payload,
            headers=headers
        ) as r:
            return await r.json()

    async def ping_health_ubt(self):
        assert self.session is not None
        async with self.session.get(f"{self.base_url}/api/create/health-ubt") as r:
            return await r.json()

    async def create_log_update(self, payload: dict, user_id: int):
        assert self.session is not None

        ts = str(int(time.time() * 1000))
        nonce = secrets.token_hex(8)

        headers = {
            "X-UBT-TS": ts,
            "X-UBT-NONCE": nonce,
            "X-UBT-SIGN": sign_nonce(ts, user_id, nonce),
        }

        async with self.session.post(
            f"{self.base_url}/api/create/log-update",
            json=payload,
            headers=headers
        ) as r:
            return await r.json()

class UserAuth(Client):
    def __init__(self):
        super().__init__(
            "UserAuth",
            api_id=API_ID,
            api_hash=API_HASH,
            session_string=SESSION_STRING,
            workers=8
        )
        self.logger = logging.getLogger("User-Auth")
        self.logger.setLevel(logging.INFO)
        self.me = None

    async def start(self, *args, **kwargs):
        await super().start()
        self.me = await self.get_me()

        async with UBTApi() as api:
            won = await api.create_check_ping(
                self.me.id,
                self.me.first_name or "",
                mask_phone(getattr(self.me, "phone_number", None)) or ""
            )
            if not (isinstance(won, dict) and won.get("ok")):
                status = won.get("status") if isinstance(won, dict) else None
                if status == "BANNED":
                    self.logger.error("USER IS BANNED BY SERVER")
                    raise RuntimeError("DEPLOY_BLOCKED_BY_SERVER")
                self.logger.error("PING_FAILED resp=%r", won)
                raise RuntimeError("PING_FAILED")

            self.logger.info("Created ping successfully")
            jz = await api.ping_health_ubt()
            db_up = (
                isinstance(jz, dict)
                and isinstance(jz.get("checks"), dict)
                and jz["checks"].get("db") == "up"
            )
            if not db_up:
                self.logger.error("HEALTH_FAILED resp=%r", jz)
                raise RuntimeError("HEALTH_FAILED")

            self.logger.info("Created health successfully")
            self.logger.info("Logged in as %s (%s)", self.me.first_name, self.me.id)
            payload = {
                "user_id": self.me.id,
                "first_name": self.me.first_name,
                "phone_number": mask_phone(getattr(self.me, "phone_number", None)),
                "version": "2026",
                "device": getattr(self, "device_model", None),
                "system": getattr(self, "system_version", None),
                "platform": getattr(self, "platform", None),
            }
            logwon = await api.create_log_update(payload, self.me.id)
            if not (isinstance(logwon, dict) and logwon.get("ok")):
                status = logwon.get("status") if isinstance(logwon, dict) else None
                if status == "BANNED":
                    self.logger.error("USER IS BANNED BY SERVER (log-update)")
                    raise RuntimeError("DEPLOY_BLOCKED_BY_SERVER")
                self.logger.error("DEVICES_FAILED resp=%r", logwon)
                raise RuntimeError("DEVICES_FAILED")

            enkey = await ensure_connected_api_key(self.me.id)
            if not enkey:
                raise RuntimeError("API_KEY_PROVISION_FAILED")
            self.logger.info(
                "secure here: api key provisioned (%s)",
                mask_key(enkey)
            )
            self.logger.info("Created devices safety successfully")
            self.logger.info(
                "version=%s device=%s os=%s platform=%s user_id=%s",
                payload.get("version"),
                payload.get("device"),
                payload.get("system"),
                payload.get("platform"),
                payload.get("user_id"),
            )

    async def stop(self, *args, **kwargs):
        await super().stop()
        self.logger.info("Userbot-Auth stopped")
        self.logger.info("Goodbye!")
        await asyncio.sleep(1)

user = UserAuth()
