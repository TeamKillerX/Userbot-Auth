from __future__ import annotations

import asyncio
import functools
from typing import Any, Awaitable, Callable, Dict, Optional, TypeVar, cast

T = TypeVar("T")

class UBTGuardError(RuntimeError):
    ...

class UBTBannedError(UBTGuardError):
    pass

class UBTDisconnectedError(UBTGuardError):
    pass

class UBTUnauthorizedError(UBTGuardError):
    pass

class UBTNetworkError(UBTGuardError):
    pass

def _dig_status(payload: Any) -> Optional[str]:
    if not isinstance(payload, dict):
        return None

    data = payload.get("data")
    if isinstance(data, dict):
        s = data.get("status")
        if isinstance(s, str) and s:
            return s
        r = data.get("reason")
        if isinstance(r, str) and r:
            return r
    err = payload.get("error")
    if isinstance(err, str) and err:
        return err
    return None

def _dig_ok(payload: Any) -> Optional[bool]:
    if not isinstance(payload, dict):
        return None
    data = payload.get("data")
    if isinstance(data, dict) and "ok" in data:
        return bool(data.get("ok"))
    if "ok" in payload:
        return bool(payload.get("ok"))
    return None

def guard(
    *,
    strict: bool = True,
    retries: int = 0,
    retry_sleep: float = 0.8,
    name: Optional[str] = None,
) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T | Dict[str, Any]]]]:
    def deco(fn: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T | Dict[str, Any]]]:
        fn_name = name or fn.__name__
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> T | Dict[str, Any]:
            last_exc: Optional[BaseException] = None

            for attempt in range(retries + 1):
                try:
                    res = await fn(*args, **kwargs)
                    status = _dig_status(res)
                    ok = _dig_ok(res)

                    if status == "BANNED":
                        if strict:
                            raise UBTBannedError(f"{fn_name}: DEPLOY_BLOCKED_BY_SERVER (BANNED)")
                        return {"ok": False, "error": "BANNED", "where": fn_name, "data": res}

                    if status in ("DISCONNECTED", "NOT_ALLOWED_IN_LOGIN", "OAUTH_NOT_CONNECTED"):
                        if strict:
                            raise UBTDisconnectedError(f"{fn_name}: USERBOT_DISCONNECTED_BY_SERVER ({status})")
                        return {"ok": False, "error": "DISCONNECTED", "where": fn_name, "data": res}

                    http = res.get("http") if isinstance(res, dict) else None
                    if http in (401, 403) and ok is False:
                        if strict:
                            raise UBTUnauthorizedError(f"{fn_name}: UNAUTHORIZED http={http} status={status}")
                        return {"ok": False, "error": "UNAUTHORIZED", "where": fn_name, "data": res}
                    return res
                except (asyncio.TimeoutError,) as e:
                    last_exc = e
                except UBTGuardError:
                    raise
                except Exception as e:
                    last_exc = e
                if attempt < retries:
                    await asyncio.sleep(retry_sleep * (attempt + 1))
                    continue
            if strict:
                raise UBTNetworkError(f"{fn_name}: NETWORK_ERROR: {last_exc}") from last_exc
            return {"ok": False, "error": "NETWORK_ERROR", "where": fn_name, "detail": str(last_exc)}
        return cast(Callable[..., Awaitable[T | Dict[str, Any]]], wrapper)
    return deco
