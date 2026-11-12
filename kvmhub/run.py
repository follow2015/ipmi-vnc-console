"""Run loopback-only services in separate processes for a local development PoC."""
import argparse
import asyncio
import multiprocessing
from pathlib import Path

import uvicorn
from aiohttp import web

from .common import (BMC_PORT, INTERNAL_PORT, UI_ORIGIN, UI_PORT, WORKER_PORT,
                     config, server_tls)


def manager_process(path):
    from .manager import build_apps
    cfg = config(path)
    ui, internal = build_apps(cfg)

    async def serve():
        common = dict(host="127.0.0.1", ssl_certfile=cfg["server_cert"], ssl_keyfile=cfg["server_key"],
                      access_log=False, log_level="warning", proxy_headers=False)
        public = uvicorn.Server(uvicorn.Config(ui, port=UI_PORT, **common))
        import ssl
        private = uvicorn.Server(uvicorn.Config(internal, port=INTERNAL_PORT, ssl_ca_certs=cfg["ca"],
                                               ssl_cert_reqs=ssl.CERT_REQUIRED, **common))
        await asyncio.gather(public.serve(), private.serve())
    asyncio.run(serve())


def worker_process(path):
    from .worker import create_worker
    cfg = config(path)
    web.run_app(create_worker(cfg), host="127.0.0.1", port=WORKER_PORT,
                ssl_context=server_tls(cfg["server_cert"], cfg["server_key"]), access_log=None, print=None)


def mock_process(path):
    from .mock_bmc import create_mock
    cfg = config(path)
    web.run_app(create_mock(cfg["username"], cfg["password"]), host="127.0.0.1", port=BMC_PORT,
                ssl_context=server_tls(cfg["cert"], cfg["key"]), access_log=None, print=None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", default=".local")
    args = parser.parse_args()
    directory = Path(args.directory).resolve()
    paths = [(manager_process, directory/"manager.json"), (worker_process, directory/"worker.json"),
             (mock_process, directory/"mock.json")]
    if any(not p.exists() for _, p in paths):
        parser.error("Run tools/bootstrap.py first")
    marker = directory / "started"
    try:
        with marker.open("x") as f:
            f.write("fresh fixture directory required for each run\n")
    except FileExistsError:
        parser.error("This fixture was already started. Bootstrap a fresh --directory (new instance_id).")
    ctx = multiprocessing.get_context("spawn")
    processes = [ctx.Process(target=fn, args=(str(p),), name=fn.__name__) for fn, p in paths]
    try:
        for process in processes:
            process.start()
        print(f"Manager: {UI_ORIGIN} (loopback only; synthetic BMC)", flush=True)
        print(f"TLS CA: {directory/'ca.pem'}\nLogin token file: {directory/'login-token'}", flush=True)
        while all(p.is_alive() for p in processes):
            for p in processes:
                p.join(timeout=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        for p in processes:
            if p.is_alive():
                p.terminate()
        for p in processes:
            p.join(timeout=8)
            if p.is_alive():
                p.kill()
                p.join()


if __name__ == "__main__":
    main()
