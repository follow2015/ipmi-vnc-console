"""First-party managed decoder child, started via multiprocessing spawn."""
import os
import struct
import time

from .runtime import (ERROR, RESET, RESET_FAMILY, SESSION_CPU_LIMIT, Message,
                      READY, SHUTDOWN, SIGNAL, UPDATE, VideoProtocolError,
                      read_frame, send_frame)
from .wire import pack_update


class _FamilySessionDecoder:

    def __init__(self, plugin):
        self.plugin = plugin

    def init(self, width, height, header=b''):
        return self.plugin.init(width, height, header)

    def feed(self, stream, width, height, header):
        return self.plugin.feed(stream)


def child_main(conn, nonce, cpu_budget, session_cpu=SESSION_CPU_LIMIT):
    _WINDOWS_KEEP = ('SystemRoot', 'windir', 'PATH', 'TEMP', 'TMP')
    kept = ({k: os.environ[k] for k in _WINDOWS_KEEP if k in os.environ}
            if os.name == 'nt' else {})
    os.environ.clear()
    os.environ.update(kept)
    try:
        if os.name == 'posix':
            import resource
            soft = max(1, int(session_cpu))
            resource.setrlimit(resource.RLIMIT_CPU, (soft, soft + 1))
        send_frame(conn, nonce, Message(
            0, 0, READY, b'KVIDEO1|' + ','.join(sorted(os.environ)).encode('utf-8')[:512]))
        decoder = None
        width = height = 0
        header = b''
        while True:
            message = read_frame(conn, nonce)
            if message.kind == SHUTDOWN:
                return
            if message.kind in (RESET, RESET_FAMILY):
                if len(message.payload) < 8:
                    raise VideoProtocolError('video_reset_invalid')
                width, height = struct.unpack_from('>II', message.payload)
                if message.kind == RESET:
                    from .huawei import HuaweiDecoder
                    decoder = HuaweiDecoder()
                    header = message.payload[8:]
                else:
                    from pathlib import Path
                    from ..transcode.registry import build as build_family
                    if len(message.payload) < 9:
                        raise VideoProtocolError('video_reset_family_invalid')
                    size = message.payload[8]
                    if not 1 <= size <= 64 or len(message.payload) < 9 + size:
                        raise VideoProtocolError('video_reset_family_invalid')
                    family = message.payload[9:9 + size].decode('ascii')
                    root = Path(__file__).resolve().parents[2]
                    plugin = build_family(family, root)
                    decoder = _FamilySessionDecoder(plugin)
                    header = message.payload[9 + size:]
                    decoder.init(width, height, header)
                send_frame(conn, nonce, Message(
                    1, 0, SIGNAL, struct.pack('>IIII', 1, width, height, len(header))))
                continue
            if message.kind != UPDATE or decoder is None:
                raise VideoProtocolError('video_worker_state_invalid')
            started = time.process_time()
            decoded = decoder.feed(message.payload, width, height, header)
            if time.process_time() - started > cpu_budget:
                raise VideoProtocolError('video_cpu_budget')
            send_frame(conn, nonce, Message(
                decoded.update.epoch, decoded.update.seq, SIGNAL,
                pack_update(decoded.update, limit=(width, height))))
    except (VideoProtocolError, ValueError, OSError, EOFError) as exc:
        try:
            send_frame(conn, nonce, Message(
                0, 0, ERROR, str(exc).encode('utf-8')[:1024]))
        except (OSError, ValueError):
            pass
    finally:
        conn.close()
