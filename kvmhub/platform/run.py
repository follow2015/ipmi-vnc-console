"""ASGI entry point for the production control plane."""
from __future__ import annotations

import os

import uvicorn


def main() -> None:
    from .config import settings
    cfg = settings()
    host = os.getenv("KVMHUB_API_HOST", "0.0.0.0" if cfg.is_prod else "127.0.0.1")
    port = int(os.getenv("KVMHUB_API_PORT", "18080"))
    uvicorn.run("kvmhub.platform.api:create_app", factory=True, host=host, port=port,
                log_level=os.getenv("KVMHUB_LOG_LEVEL", "info"),
                proxy_headers=True, forwarded_allow_ips="127.0.0.1")


if __name__ == "__main__":
    main()
