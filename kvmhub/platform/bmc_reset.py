"""Out-of-band BMC management-controller reset (platform maintenance action)."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 15
WAIT_MARGIN = 5


class ResetError(Exception):

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


def _validate_address(address: str) -> str:
    try:
        return str(ipaddress.ip_address(address.strip()))
    except (ValueError, AttributeError):
        raise ResetError("bmc_address_invalid", "BMC 地址不是合法的 IP") from None


def _cold_reset_sync(address: str, username: str, password: str,
                     timeout: int) -> dict[str, Any]:
    try:
        from pyghmi.ipmi import command as ipmi_command
    except ImportError:
        raise ResetError("ipmi_unavailable", "IPMI 支持未安装（缺少 pyghmi）") from None

    try:
        conn = ipmi_command.Command(bmc=address, userid=username,
                                    password=password, timeout=timeout)
    except Exception as exc:
        raise ResetError("ipmi_auth_failed", f"IPMI 认证或连接失败: {type(exc).__name__}") from None

    try:
        result = conn.reset_bmc()
        return {"accepted": True, "result": str(result) if result is not None else "cold"}
    except Exception as exc:
        raise ResetError("ipmi_reset_failed", f"IPMI 复位命令失败: {type(exc).__name__}") from None


async def cold_reset_bmc(address: str, username: str, password: str,
                         *, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    target = _validate_address(address)
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_cold_reset_sync, target, username, password, timeout),
            timeout=timeout + WAIT_MARGIN)
    except ResetError:
        raise
    except asyncio.TimeoutError:
        raise ResetError("ipmi_timeout", "IPMI 复位超时") from None
    except Exception as exc:
        raise ResetError("ipmi_error", f"IPMI 复位异常: {type(exc).__name__}") from None
