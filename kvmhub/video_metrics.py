"""Opt-in bounded counters for the existing video path, never frame content."""
from contextlib import contextmanager
import time


class VideoMetrics:
    def __init__(self):
        self.started = time.monotonic()
        self.source_updates = 0
        self.source_bytes = 0
        self.encoded_bytes = 0
        self.encoded_messages = 0
        self.queued_video_bytes = 0
        self.kind_counts = [0] * 8
        self.unknown_blocks = 0
        self.truncated_blocks = 0
        self.missing_copy_sources = 0
        self.geometry_changes = 0
        self.stage_wall = {key: 0.0 for key in ('decode_convert', 'encode', 'enqueue')}
        self.stage_cpu = {key: 0.0 for key in ('decode_convert', 'encode')}
        self.stage_max_wall = {key: 0.0 for key in self.stage_wall}

    @contextmanager
    def measure(self, stage):
        wall, cpu = time.perf_counter(), time.thread_time()
        try:
            yield
        finally:
            elapsed = time.perf_counter() - wall
            self.stage_wall[stage] += elapsed
            self.stage_cpu[stage] += time.thread_time() - cpu
            self.stage_max_wall[stage] = max(self.stage_max_wall[stage], elapsed)

    def messages(self, source):
        iterator = iter(source)
        while True:
            with self.measure('encode'):
                try:
                    message = next(iterator)
                except StopIteration:
                    return
            self.encoded_messages += 1
            self.encoded_bytes += len(message)
            yield message

    def public(self):
        elapsed = max(0.0, time.monotonic() - self.started)
        return {
            'elapsed_seconds': elapsed,
            'source_updates': self.source_updates, 'source_bytes': self.source_bytes,
            'encoded_messages': self.encoded_messages, 'encoded_bytes': self.encoded_bytes,
            'queued_video_bytes': self.queued_video_bytes,
            'source_updates_per_second': self.source_updates / elapsed if elapsed else 0.0,
            'encoded_mbit_per_second': self.encoded_bytes * 8 / elapsed / 1_000_000 if elapsed else 0.0,
            'block_kinds': dict(enumerate(self.kind_counts)),
            'unknown_blocks': self.unknown_blocks, 'truncated_blocks': self.truncated_blocks,
            'missing_copy_sources': self.missing_copy_sources,
            'geometry_changes': self.geometry_changes,
            'stage_wall_seconds': dict(self.stage_wall),
            'stage_cpu_seconds': dict(self.stage_cpu),
            'stage_max_wall_seconds': dict(self.stage_max_wall),
        }
