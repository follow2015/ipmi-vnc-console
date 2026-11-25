"""Request-driven V1 video session on top of the isolated decoder process."""
from __future__ import annotations

from .encoding import encode_snapshot
from .framebuffer import Framebuffer, Rect
from .requests import RequestStream
from .runtime import (ManagedDecoder, OutputQueue, VideoBudgetError,
                      VideoProtocolError, VideoResyncRequired)


class VideoSession:
    def __init__(self, *, decoder: ManagedDecoder | None = None, tight=True,
                 max_message=65536, before_resync=None, require_resync_permit=False):
        self.decoder = decoder or ManagedDecoder(
            before_resync=before_resync, require_resync_permit=require_resync_permit)
        self.tight = tight
        self.rgbx = False
        self.max_message = max_message
        self.framebuffer: Framebuffer | None = None
        self.streams: dict[str, RequestStream] = {}
        self.queues: dict[str, OutputQueue] = {}
        self.queued: dict[str, int] = {}

    @property
    def epoch(self):
        return self.framebuffer.epoch if self.framebuffer else 0

    def _bind_framebuffer(self, width, height, epoch):
        size = width * height * 5
        self.decoder.ledger.reserve(size)
        try:
            framebuffer = Framebuffer(width, height, epoch=epoch)
        except BaseException:
            self.decoder.ledger.release(size)
            raise
        old = self.framebuffer
        if old is not None:
            self.decoder.ledger.release(old.width * old.height * 5)
        self.framebuffer = framebuffer
        return framebuffer

    def _drop_bytes(self, client_id, size):
        if size <= 0:
            return
        self.queued[client_id] = max(0, self.queued.get(client_id, 0) - size)
        self.decoder.ledger.release(size)

    def _drop_queue(self, client_id):
        self.queues.pop(client_id, None)
        self._drop_bytes(client_id, self.queued.pop(client_id, 0))

    def _reset_output(self, *, preserve_clients=False):
        for client_id in list(self.streams):
            self._drop_queue(client_id)
            if preserve_clients:
                self.queues[client_id] = OutputQueue(self.decoder.budget)
                self.queued[client_id] = 0

    def _queue(self, client_id):
        queue = self.queues.get(client_id)
        if queue is None:
            raise VideoProtocolError('video_client_unknown')
        return queue

    async def open(self, width, height, header=b''):
        if not self.decoder.running:
            self.decoder.start()
        epoch = await self.decoder.resync(width, height, header)
        self._reset_output()
        for stream in self.streams.values():
            if stream.inflight is not None:
                stream.abort(stream.inflight)
        self.streams = {}
        self._bind_framebuffer(width, height, epoch)
        return epoch

    async def resync(self, width, height, header=b''):
        if not self.decoder.running:
            self.decoder.start()
        epoch = await self.decoder.resync(width, height, header)
        self._reset_output(preserve_clients=True)
        for stream in self.streams.values():
            if stream.inflight is not None:
                stream.abort(stream.inflight)
        try:
            self._bind_framebuffer(width, height, epoch)
        except BaseException:
            self.decoder.invalidate('video_framebuffer_bind_failed')
            raise
        for stream in self.streams.values():
            stream.framebuffer = self.framebuffer
            stream.resized()
        return epoch

    def close(self):
        self._reset_output()
        for stream in self.streams.values():
            if stream.inflight is not None:
                stream.abort(stream.inflight)
        self.streams.clear()
        if self.framebuffer is not None:
            self.decoder.ledger.release(self.framebuffer.width * self.framebuffer.height * 5)
        self.framebuffer = None
        self.decoder.close()

    def attach(self, client_id):
        if self.framebuffer is None:
            raise VideoResyncRequired('video_session_not_open')
        if client_id in self.streams:
            raise VideoProtocolError('video_client_duplicate')
        self.streams[client_id] = RequestStream(self.framebuffer, ledger=self.decoder.ledger)
        self.queues[client_id] = OutputQueue(self.decoder.budget)
        self.queued[client_id] = 0

    def detach(self, client_id):
        stream = self.streams.pop(client_id, None)
        if stream is not None and stream.inflight is not None:
            stream.abort(stream.inflight)
        self._drop_queue(client_id)

    def request(self, client_id, rect, *, incremental):
        stream = self.streams.get(client_id)
        if stream is None:
            raise VideoProtocolError('video_client_unknown')
        stream.request(rect, incremental=incremental)

    async def feed(self, stream_bytes):
        if self.framebuffer is None:
            raise VideoResyncRequired('video_session_not_open')
        update = self.decoder.decode_update(stream_bytes)
        if update.epoch != self.framebuffer.epoch:
            self.decoder.invalidate('video_epoch_mismatch')
            raise VideoProtocolError('video_epoch_mismatch')
        try:
            self.framebuffer.apply(update)
        except ValueError as exc:
            self.decoder.invalidate(f'video_update_rejected:{exc}')
            raise VideoProtocolError(f'video_update_rejected: {exc}') from exc
        for client in self.streams.values():
            client.changed(update)
        return update

    def prepare(self, client_id):
        stream = self.streams.get(client_id)
        if stream is None:
            raise VideoProtocolError('video_client_unknown')
        return stream.prepare()

    def messages(self, client_id, batch):
        if batch is None:
            return
        queue = self._queue(client_id)
        limit = (self.framebuffer.width, self.framebuffer.height)
        for snapshot in batch.snapshots:
            for message in encode_snapshot(snapshot, tight=self.tight,
                                           max_message=self.max_message, limit=limit,
                                           rgbx=self.rgbx):
                self.decoder.ledger.reserve(len(message))
                try:
                    queue.enqueue(message)
                except VideoBudgetError:
                    self.decoder.ledger.release(len(message))
                    raise
                self.queued[client_id] += len(message)
                yield message

    def sent(self, client_id, batch):
        stream = self.streams.get(client_id)
        if stream is None:
            raise VideoProtocolError('video_client_unknown')
        queue = self._queue(client_id)
        queue.check()
        self._drop_bytes(client_id, len(queue.drain()))
        stream.sent(batch)


__all__ = ['VideoSession', 'Rect']
