"""Synthetic offline video pipeline benchmark: python -m kvmhub.video.bench."""
import argparse
import hashlib
import json
import platform
import statistics
import time
import tracemalloc

from .encoding import encode_snapshot
from .framebuffer import Rect
from .huawei import HuaweiDecoder
from .requests import RequestStream
from .synthetic import jpeg_block


def percentile(values, percent):
    return sorted(values)[max(0, (len(values) * percent + 99) // 100 - 1)]


def benchmark(*, width=1024, height=768, samples=300, warmup=30, workload='terminal'):
    if workload not in ('static', 'terminal', 'full') or not 1 <= samples <= 1000 or not 0 <= warmup <= 100:
        raise ValueError('invalid benchmark configuration')
    from .framebuffer import geometry
    geometry(width, height)
    blocks = ((width + 63) // 64) * ((height + 63) // 64)
    header, first = jpeg_block((220, 30, 10))
    second_header, second = jpeg_block((10, 30, 220))
    assert header == second_header
    seed_frame = first * blocks
    variants = {
        'static': (b'\x80' * blocks,) * 2,
        'terminal': (first + b'\x80' * (blocks - 1), second + b'\x80' * (blocks - 1)),
        'full': (first * blocks, second * blocks),
    }[workload]
    source_digest = hashlib.sha256(header + seed_frame + b''.join(variants)).hexdigest()
    decoder = HuaweiDecoder()
    decoder.feed(seed_frame, width, height, header)
    stream = RequestStream(decoder.framebuffer)
    full = Rect(0, 0, width, height)
    stream.request(full, incremental=False)
    batch = stream.prepare()
    list(encode_snapshot(batch.snapshots[0]))
    stream.sent(batch)
    walls, cpus, sizes = [], [], []
    for index in range(warmup + samples):
        wall, cpu = time.perf_counter(), time.process_time()
        result = decoder.feed(variants[index % 2], width, height, header)
        stream.changed(result.update)
        if not stream.pending:
            stream.request(full, incremental=True)
        batch = stream.prepare()
        encoded_bytes = 0
        if batch:
            for snapshot in batch.snapshots:
                encoded_bytes += sum(len(message) for message in encode_snapshot(snapshot))
            stream.sent(batch)
        elapsed, cpu_elapsed = time.perf_counter() - wall, time.process_time() - cpu
        if index >= warmup:
            walls.append(elapsed); cpus.append(cpu_elapsed); sizes.append(encoded_bytes)
    return {
        'synthetic': True, 'network_used': False, 'workload': workload,
        'geometry': [width, height], 'samples': samples, 'warmup': warmup,
        'generator': 'solid-jpeg-block-v1', 'source_sha256': source_digest,
        'wall_ms': {str(p): percentile(walls, p) * 1000 for p in (50,95,99)},
        'cpu_ms': {str(p): percentile(cpus, p) * 1000 for p in (50,95,99)},
        'encoded_bytes_mean': statistics.mean(sizes), 'encoded_bytes_max': max(sizes),
        'estimated_mbit_at_10_updates_per_second': statistics.mean(sizes) * 80 / 1_000_000,
        'estimated_cpu_cores_at_10_updates_per_second': statistics.mean(cpus) * 10,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--width', type=int, default=1024)
    parser.add_argument('--height', type=int, default=768)
    parser.add_argument('--samples', type=int, default=300)
    parser.add_argument('--warmup', type=int, default=30)
    parser.add_argument('--workload', choices=('static','terminal','full'), default='terminal')
    args = parser.parse_args()
    tracemalloc.start()
    result = benchmark(**vars(args))
    _, peak = tracemalloc.get_traced_memory()
    result.update({'python': platform.python_version(), 'system': platform.system(),
                   'machine': platform.machine(), 'peak_python_bytes': peak,
                   'timing_includes_tracemalloc': True,
                   'memory_scope': 'Python allocator only; not RSS, decoder native allocation or browser'})
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
