"""Enterprise security telemetry and attack scenario generator.

Synthesizes high-volume, realistic VPC flow logs, cloud identity events,
process executions, DNS queries, and multi-stage APT breach campaigns.
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import random
from typing import Any, Dict, List, Tuple


class TelemetryGenerator:
    """Generates synthetic enterprise telemetry and labeled attack campaigns."""

    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)
        self.base_time = datetime.datetime(2026, 10, 15, 8, 0, 0, tzinfo=datetime.timezone.utc)

    def generate_vpc_flow_record(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        packets: int,
        bytes_transferred: int,
        action: str,
        timestamp_offset_secs: int
    ) -> Dict[str, Any]:
        """Generates a single VPC flow log record."""
        t_start = self.base_time + datetime.timedelta(seconds=timestamp_offset_secs)
        t_end = t_start + datetime.timedelta(seconds=self.rng.randint(1, 60))
        return {
            "flow_id": f"fl-{self.rng.getrandbits(64):016x}",
            "start_time": t_start.isoformat(),
            "end_time": t_end.isoformat(),
            "src_addr": src_ip,
            "dst_addr": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "packets": packets,
            "bytes_transferred": bytes_transferred,
            "action": action,
            "log_status": "OK"
        }

    def generate_beaconing_series(
        self,
        c2_ip: str,
        victim_ip: str,
        interval_secs: int = 60,
        jitter_pct: float = 0.10,
        count: int = 50
    ) -> List[Dict[str, Any]]:
        """Generates a series of periodic C2 beaconing connections with jitter."""
        flows = []
        current_offset = 0
        for _ in range(count):
            jitter = (self.rng.random() * 2 - 1) * (interval_secs * jitter_pct)
            delta = int(interval_secs + jitter)
            current_offset += max(1, delta)
            flows.append(
                self.generate_vpc_flow_record(
                    src_ip=victim_ip,
                    dst_ip=c2_ip,
                    src_port=self.rng.randint(49152, 65535),
                    dst_port=443,
                    protocol=6,
                    packets=self.rng.randint(5, 12),
                    bytes_transferred=self.rng.randint(450, 1200),
                    action="ACCEPT",
                    timestamp_offset_secs=current_offset
                )
            )
        return flows
