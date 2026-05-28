"""Per-phase timing + throughput report."""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator, Optional

from baleharness.logutil import fmt_bytes, info


@dataclass
class TimingEntry:
    name: str
    elapsed_s: float
    bytes_moved: int = 0  # populated only for throughput-relevant phases

    def throughput_mb_s(self) -> Optional[float]:
        if self.bytes_moved <= 0 or self.elapsed_s <= 0:
            return None
        return (self.bytes_moved / (1024 * 1024)) / self.elapsed_s


@dataclass
class Timings:
    entries: list[TimingEntry] = field(default_factory=list)

    @contextmanager
    def measure(self, name: str, *, bytes_moved: int = 0) -> Iterator[None]:
        info(f">>> phase: {name}")
        t0 = time.perf_counter()
        try:
            yield
        finally:
            elapsed = time.perf_counter() - t0
            self.entries.append(TimingEntry(name, elapsed, bytes_moved))
            tp = ""
            if bytes_moved > 0 and elapsed > 0:
                mbps = (bytes_moved / (1024 * 1024)) / elapsed
                tp = f"  [{mbps:.2f} MiB/s on {fmt_bytes(bytes_moved)}]"
            info(f"<<< {name}: {elapsed:.2f}s{tp}")

    def print_report(self) -> None:
        if not self.entries:
            return
        print("\n=== Timing summary ===", flush=True)
        name_w = max(len(e.name) for e in self.entries)
        total = 0.0
        for e in self.entries:
            total += e.elapsed_s
            tp = e.throughput_mb_s()
            tp_s = f"  {tp:6.2f} MiB/s ({fmt_bytes(e.bytes_moved)})" if tp else ""
            print(f"  {e.name.ljust(name_w)}  {e.elapsed_s:7.2f}s{tp_s}", flush=True)
        print(f"  {'TOTAL'.ljust(name_w)}  {total:7.2f}s", flush=True)
