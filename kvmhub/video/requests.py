"""Per-client request-driven updates; state advances only after a completed send."""
from dataclasses import dataclass

from .framebuffer import Framebuffer, Rect, Snapshot, Update, MAX_RECTS, MAX_UPDATE_BYTES

MAX_PENDING_REQUESTS = 32


@dataclass(frozen=True)
class Prepared:
    epoch: int
    seq: int
    request_ids: tuple
    snapshots: tuple[Snapshot, ...]


class RequestStream:
    def __init__(self, framebuffer: Framebuffer, *, ledger=None):
        self.framebuffer = framebuffer
        self.epoch = framebuffer.epoch
        self.pending = []
        self.dirty = [(framebuffer.seq, Rect(0, 0, framebuffer.width, framebuffer.height))]
        self.serial = 0
        self.dropped_requests = 0
        self.inflight = None
        self.ledger = ledger
        self.snapshot_bytes = 0

    def _release_snapshots(self):
        if self.ledger is not None:
            self.ledger.release(self.snapshot_bytes)
        self.snapshot_bytes = 0

    def _check_epoch(self):
        if self.epoch != self.framebuffer.epoch:
            raise ValueError('video_stream_resize_required')

    def resized(self):
        if self.inflight is not None:
            raise ValueError('video_send_in_progress')
        self.epoch = self.framebuffer.epoch
        self.pending.clear()
        self.dirty = [(self.framebuffer.seq, Rect(0, 0, self.framebuffer.width, self.framebuffer.height))]

    def request(self, rect, *, incremental):
        self._check_epoch()
        rect.validate(self.framebuffer.width, self.framebuffer.height)
        if type(incremental) is not bool:
            raise ValueError('video_request_invalid')
        if any(item[1] == rect and item[2] == incremental for item in self.pending):
            return
        if len(self.pending) >= MAX_PENDING_REQUESTS:
            self.dropped_requests += 1
            return
        self.serial += 1
        self.pending.append((self.serial, rect, incremental))

    def changed(self, update: Update):
        self._check_epoch()
        if update.epoch != self.epoch or update.seq != self.framebuffer.seq:
            raise ValueError('video_dirty_sequence_invalid')
        self.dirty.extend((update.seq, op.rect) for op in update.operations)
        if len(self.dirty) > MAX_RECTS:
            self.dirty = [(update.seq, Rect(0, 0, self.framebuffer.width, self.framebuffer.height))]

    def prepare(self):
        self._check_epoch()
        if self.inflight is not None:
            raise ValueError('video_send_in_progress')
        snapshots, ids, byte_size = [], [], 0
        try:
            for request_id, rect, incremental in self.pending:
                if incremental and not any(rect.intersection(dirty) for _, dirty in self.dirty):
                    continue
                size = rect.w * rect.h * 4
                if byte_size + size > MAX_UPDATE_BYTES:
                    raise ValueError('video_snapshot_budget')
                if self.ledger is not None:
                    self.ledger.reserve(size)
                self.snapshot_bytes += size
                snapshot = self.framebuffer.snapshot(rect)
                if snapshot is None:
                    if self.ledger is not None:
                        self.ledger.release(size)
                    self.snapshot_bytes -= size
                    continue
                byte_size += size
                snapshots.append(snapshot)
                ids.append(request_id)
        except BaseException:
            self._release_snapshots()
            raise
        if not snapshots:
            return None
        self.inflight = Prepared(self.epoch, self.framebuffer.seq, tuple(ids), tuple(snapshots))
        return self.inflight

    def sent(self, batch):
        self._check_epoch()
        if self.inflight is not batch:
            raise ValueError('video_send_token_invalid')
        remaining = self.dirty
        for snapshot in batch.snapshots:
            remaining = [(seq, piece) for seq, rect in remaining
                         for piece in (rect.subtract(snapshot.rect) if seq <= batch.seq else [rect])]
            if len(remaining) > MAX_RECTS:
                remaining = [(self.framebuffer.seq,
                              Rect(0, 0, self.framebuffer.width, self.framebuffer.height))]
                break
        self.dirty = remaining
        self.pending = [request for request in self.pending if request[0] not in batch.request_ids]
        self.inflight = None
        self._release_snapshots()

    def abort(self, batch):
        if self.inflight is not batch:
            raise ValueError('video_send_token_invalid')
        self.inflight = None
        self._release_snapshots()
