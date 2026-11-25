"""Opt-in V1 video runtime: isolated decoder process, strict IPC and budgets."""
import hmac
import multiprocessing
import os
import secrets
import struct
import time
from dataclasses import dataclass

from .framebuffer import MAX_PIXELS, MAX_RECTS, MAX_UPDATE_BYTES, geometry

IPC_MAGIC = b'KVD1'
IPC_VERSION = 1
HEADER = struct.Struct('>4sB16sIIBI')
NONCE_SIZE = 16

RESET = 1
UPDATE = 2
SIGNAL = 3
ERROR = 4
READY = 5
SHUTDOWN = 6
RESET_FAMILY = 7
KINDS = frozenset((RESET, UPDATE, SIGNAL, ERROR, READY, SHUTDOWN, RESET_FAMILY))

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_SESSION_INPUT_BYTES = 512 * 1024 * 1024
MAX_SESSION_BYTES = 256 * 1024 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
OUTPUT_AGE_LIMIT = 0.5
DECODE_CPU_BUDGET = 2.0
SESSION_CPU_LIMIT = 900.0
DECODE_WALL_LIMIT = 2.0
TERMINATE_GRACE = 0.5


class VideoProtocolError(ValueError):
    pass


class VideoBudgetError(ValueError):
    pass


class VideoUnsupported(RuntimeError):
    pass


class VideoResyncRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class Message:
    epoch: int
    seq: int
    kind: int
    payload: bytes = b''


@dataclass(frozen=True)
class VideoBudget:
    max_width: int = 4096
    max_height: int = 2160
    max_pixels: int = MAX_PIXELS
    max_rects: int = MAX_RECTS
    max_event_bytes: int = MAX_UPDATE_BYTES
    max_input_bytes: int = MAX_INPUT_BYTES
    max_total_input_bytes: int = MAX_SESSION_INPUT_BYTES
    max_session_bytes: int = MAX_SESSION_BYTES
    max_output_bytes: int = MAX_OUTPUT_BYTES
    output_age: float = OUTPUT_AGE_LIMIT
    decode_cpu: float = DECODE_CPU_BUDGET
    decode_session_cpu: float = SESSION_CPU_LIMIT
    decode_wall: float = DECODE_WALL_LIMIT

    def __post_init__(self):
        for name in ('max_width', 'max_height', 'max_pixels', 'max_rects',
                     'max_event_bytes', 'max_input_bytes', 'max_total_input_bytes',
                     'max_session_bytes', 'max_output_bytes'):
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise VideoBudgetError('video_budget_invalid')
        for name in ('output_age', 'decode_cpu', 'decode_session_cpu', 'decode_wall'):
            if type(getattr(self, name)) not in (int, float) or getattr(self, name) <= 0:
                raise VideoBudgetError('video_budget_invalid')
        if self.decode_session_cpu <= self.decode_cpu:
            raise VideoBudgetError('video_budget_invalid')

    def check_geometry(self, width, height):
        geometry(width, height)
        if width > self.max_width or height > self.max_height or width * height > self.max_pixels:
            raise VideoBudgetError('video_geometry_budget')

    def check_event(self, rects, payload_bytes):
        if type(rects) is not int or rects < 0 or rects > self.max_rects:
            raise VideoBudgetError('video_rects_budget')
        if (type(payload_bytes) is not int or payload_bytes < 0
                or payload_bytes > min(self.max_event_bytes, MAX_UPDATE_BYTES)):
            raise VideoBudgetError('video_payload_budget')


def encode_message(nonce, message):
    if type(nonce) is not bytes or len(nonce) != NONCE_SIZE:
        raise VideoProtocolError('video_ipc_nonce_invalid')
    if (type(message.epoch) is not int or not 0 <= message.epoch < 2 ** 32
            or type(message.seq) is not int or not 0 <= message.seq < 2 ** 32):
        raise VideoProtocolError('video_ipc_sequence_invalid')
    if type(message.kind) is not int or message.kind not in KINDS:
        raise VideoProtocolError('video_ipc_kind_invalid')
    if type(message.payload) is not bytes or len(message.payload) > MAX_UPDATE_BYTES:
        raise VideoProtocolError('video_ipc_payload_invalid')
    return HEADER.pack(IPC_MAGIC, IPC_VERSION, nonce, message.epoch, message.seq,
                       message.kind, len(message.payload)) + message.payload


def decode_message(raw, nonce):
    if type(raw) is not bytes or len(raw) < HEADER.size:
        raise VideoProtocolError('video_ipc_header_truncated')
    magic, version, peer_nonce, epoch, seq, kind, size = HEADER.unpack_from(raw)
    if not hmac.compare_digest(magic, IPC_MAGIC) or version != IPC_VERSION:
        raise VideoProtocolError('video_ipc_version_invalid')
    if not hmac.compare_digest(peer_nonce, nonce):
        raise VideoProtocolError('video_ipc_session_invalid')
    if kind not in KINDS or not 0 <= epoch < 2 ** 32 or not 0 <= seq < 2 ** 32:
        raise VideoProtocolError('video_ipc_header_invalid')
    if size > MAX_UPDATE_BYTES:
        raise VideoProtocolError('video_ipc_length_invalid')
    if len(raw) - HEADER.size < size:
        raise VideoProtocolError('video_ipc_payload_truncated')
    if len(raw) - HEADER.size != size:
        raise VideoProtocolError('video_ipc_length_invalid')
    return Message(epoch, seq, kind, raw[HEADER.size:])


def send_frame(conn, nonce, message):
    conn.send_bytes(encode_message(nonce, message))


def read_frame(conn, nonce, timeout=None):
    if not conn.poll(timeout):
        raise TimeoutError('video_ipc_timeout')
    return decode_message(conn.recv_bytes(), nonce)


class BudgetLedger:

    def __init__(self, budget: VideoBudget):
        self.budget = budget
        self.memory = 0
        self.input = 0
        self.inflight = False

    def reserve(self, size):
        if type(size) is not int or size < 0:
            raise VideoBudgetError('video_memory_budget')
        if self.memory + size > self.budget.max_session_bytes:
            raise VideoBudgetError('video_memory_budget')
        self.memory += size

    def release(self, size):
        if type(size) is not int or size < 0:
            raise VideoBudgetError('video_memory_budget')
        self.memory = max(0, self.memory - size)

    def begin_input(self, size):
        if self.inflight:
            raise VideoBudgetError('video_decode_in_progress')
        if (type(size) is not int or size < 0
                or size > min(self.budget.max_input_bytes, MAX_UPDATE_BYTES)):
            raise VideoBudgetError('video_input_budget')
        if self.input + size > self.budget.max_total_input_bytes:
            raise VideoBudgetError('video_input_budget')
        self.inflight = True
        self.input += size

    def end_input(self):
        self.inflight = False


class OutputQueue:

    def __init__(self, budget: VideoBudget, *, clock=time.monotonic):
        self.budget = budget
        self.clock = clock
        self.data = bytearray()
        self.oldest = None

    def enqueue(self, payload, now=None):
        now = self.clock() if now is None else now
        if type(payload) is not bytes:
            raise VideoBudgetError('video_output_invalid')
        if len(self.data) + len(payload) > self.budget.max_output_bytes:
            raise VideoBudgetError('video_output_queue_budget')
        if not self.data:
            self.oldest = now
        self.data.extend(payload)

    def check(self, now=None):
        now = self.clock() if now is None else now
        if self.data and now - self.oldest > self.budget.output_age:
            raise VideoBudgetError('video_output_age')

    def drain(self):
        payload = bytes(self.data)
        self.data.clear()
        self.oldest = None
        return payload


def hard_cpu_limit_supported():
    return os.name == 'posix' and hasattr(__import__('resource'), 'RLIMIT_CPU')


class ManagedDecoder:

    def __init__(self, *, nonce=None, budget=None, require_hard_cpu_limit=True,
                 before_resync=None, require_resync_permit=False):
        self.nonce = nonce if nonce is not None else secrets.token_bytes(16)
        self.budget = budget or VideoBudget()
        self.require_hard_cpu_limit = require_hard_cpu_limit
        self.before_resync = before_resync
        self.require_resync_permit = require_resync_permit
        self.ledger = BudgetLedger(self.budget)
        self.proc = None
        self.conn = None
        self.epoch = 0
        self.needs_resync = True
        self.permit_pending = False
        self.last_error = ''

    @property
    def running(self):
        return self.proc is not None and self.proc.is_alive()

    def _reap(self):
        proc = self.proc
        if proc is None or proc.is_alive():
            return False
        self._failed('video_decoder_exited')
        return True

    def start(self):
        if self.proc is not None and not self._reap():
            raise VideoUnsupported('video_decoder_already_started')
        if self.require_hard_cpu_limit and not hard_cpu_limit_supported():
            raise VideoUnsupported('video_hard_cpu_limit_unavailable')
        from .decoder_worker import child_main

        ctx = multiprocessing.get_context('spawn')
        parent, child = ctx.Pipe(duplex=True)
        self.proc = ctx.Process(target=child_main,
                                args=(child, self.nonce, self.budget.decode_cpu,
                                      self.budget.decode_session_cpu),
                                name='kvmhub-video-decoder', daemon=True)
        self.proc.start()
        child.close()
        self.conn = parent
        try:
            ready = self._read(self.budget.decode_wall)
            if ready.kind != READY:
                raise VideoProtocolError('video_decoder_not_ready')
        except BaseException:
            self._failed('video_decoder_not_ready')
            raise
        return ready

    def _read(self, timeout):
        try:
            return read_frame(self.conn, self.nonce, timeout)
        except (OSError, EOFError, TimeoutError, VideoProtocolError) as exc:
            self._failed(str(exc))
            raise

    def _send(self, message):
        try:
            send_frame(self.conn, self.nonce, message)
        except (OSError, ValueError) as exc:
            self._failed(str(exc))
            raise

    def _failed(self, reason):
        self.last_error = reason
        self.epoch = 0
        self.needs_resync = True
        self.permit_pending = self.require_resync_permit
        self.ledger.end_input()
        self._kill()

    def invalidate(self, reason):
        self._failed(reason)

    @staticmethod
    def _error_code(payload):
        try:
            text = payload.decode('utf-8', 'replace')
        except Exception:  # pragma: no cover - decode with replace cannot fail
            return ''
        text = text.strip().splitlines()[0][:120] if text.strip() else ''
        allowed = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
                      '0123456789:_-. ')
        return text if text and set(text) <= allowed else ''

    async def resync(self, width, height, header=b'', family=None):
        self._reap()
        if self.permit_pending:
            if self.before_resync is None:
                raise VideoResyncRequired('video_resync_permit_missing')
            await self.before_resync()
            self.permit_pending = False
        if not self.running:
            self.start()
        return self.reset(width, height, header, family=family)

    def reset(self, width, height, header=b'', family=None):
        if self.permit_pending:
            raise VideoResyncRequired('video_resync_permit_missing')
        self._reap()
        if not self.running:
            raise VideoUnsupported('video_decoder_not_running')
        self.budget.check_geometry(width, height)
        if type(header) is not bytes or len(header) > 4096:
            raise VideoProtocolError('video_ipc_header_invalid')
        if family is None:
            payload = struct.pack('>II', width, height) + header
            kind = RESET
        else:
            if (type(family) is not str or not family or len(family) > 64
                    or any(ord(ch) < 33 or ord(ch) > 126 for ch in family)):
                raise VideoProtocolError('video_family_invalid')
            payload = (struct.pack('>IIB', width, height, len(family))
                       + family.encode('ascii') + header)
            kind = RESET_FAMILY
        self._send(Message(0, 0, kind, payload))
        answer = self._read(self.budget.decode_wall)
        if answer.kind == ERROR:
            reason = self._error_code(answer.payload) or 'unspecified'
            self._failed(f'video_decoder_rejected_reset:{reason}')
            raise VideoProtocolError(f'video_decoder_rejected_reset: {reason}')
        if answer.kind != SIGNAL or len(answer.payload) < 4:
            raise VideoProtocolError('video_decoder_reset_reply_invalid')
        epoch = int.from_bytes(answer.payload[:4], 'big')
        if epoch < 1:
            raise VideoProtocolError('video_decoder_reset_reply_invalid')
        self.budget.check_event(1, len(answer.payload))
        self.epoch = epoch
        self.needs_resync = False
        return self.epoch

    def decode(self, stream):
        if self.needs_resync or not self.running:
            raise VideoResyncRequired('video_resync_required')
        if type(stream) is not bytes:
            raise VideoProtocolError('video_ipc_payload_invalid')
        self.ledger.begin_input(len(stream))
        try:
            self._send(Message(self.epoch, 0, UPDATE, stream))
            answer = self._read(self.budget.decode_wall)
        except TimeoutError:
            self._failed('video_decode_timeout')
            raise VideoBudgetError('video_decode_timeout') from None
        except (OSError, EOFError, VideoProtocolError):
            raise
        finally:
            self.ledger.end_input()
        if answer.kind == ERROR:
            reason = self._error_code(answer.payload) or 'unspecified'
            self._failed(f'video_decode_rejected:{reason}')
            raise VideoProtocolError(f'video_decode_rejected: {reason}')
        if answer.kind != SIGNAL or answer.epoch != self.epoch:
            self._failed('video_decoder_epoch_invalid')
            raise VideoProtocolError('video_decoder_epoch_invalid')
        rects = int.from_bytes(answer.payload[:4], 'big') if answer.payload else 0
        try:
            self.budget.check_event(rects, len(answer.payload))
        except VideoBudgetError as exc:
            self._failed(str(exc))
            raise
        return answer

    def decode_update(self, stream):
        from .wire import unpack_update
        answer = self.decode(stream)
        try:
            return unpack_update(answer.payload,
                                 limit=(self.budget.max_width, self.budget.max_height))
        except ValueError as exc:
            self._failed(str(exc))
            raise VideoProtocolError(str(exc)) from exc

    def _kill(self):
        proc, self.proc = self.proc, None
        self.needs_resync = True
        self.epoch = 0
        if self.require_resync_permit:
            self.permit_pending = True
        if self.conn is not None:
            try:
                self.conn.close()
            except OSError:
                pass
            self.conn = None
        if proc is None:
            return
        if proc.is_alive():
            proc.terminate()
            proc.join(TERMINATE_GRACE)
            if proc.is_alive():
                proc.kill()
                proc.join()
        else:
            proc.join()

    def close(self):
        self._kill()
        self.needs_resync = True
        self.epoch = 0
        self.permit_pending = False
        self.ledger.inflight = False
