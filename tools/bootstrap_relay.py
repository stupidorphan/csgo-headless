#!/usr/bin/env python3
"""Development UDP relay for the one explicitly authorized server.

Connectionless packets, including Steam authentication, are forwarded but never
recorded. Captures are local development data and must not be committed.
"""
from __future__ import annotations

import argparse
import json
import select
import socket
import time
from pathlib import Path

LISTEN = ("127.0.0.2", 27016)
UPSTREAM = ("151.243.93.16", 27015)
CONNECTIONLESS = b"\xff\xff\xff\xff"


def capture_record(direction: str, payload: bytes, timestamp_ns: int | None = None) -> dict | None:
    if len(payload) < 4 or payload.startswith(CONNECTIONLESS):
        return None
    if direction not in ("client_to_server", "server_to_client"):
        raise ValueError("invalid relay direction")
    return {"timestamp_ns": time.monotonic_ns() if timestamp_ns is None else timestamp_ns,
            "direction": direction, "hex": payload.hex()}


def run(capture: Path, duration: float = 0) -> None:
    if duration < 0:
        raise ValueError("duration cannot be negative")
    capture.parent.mkdir(parents=True, exist_ok=True)
    client = None
    last_client = 0.0
    started = time.monotonic()
    stats = {"client_to_server": 0, "server_to_client": 0, "recorded": 0, "excluded": 0}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as local, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as remote, capture.open("x", encoding="utf-8", buffering=1) as output:
        local.bind(LISTEN)
        remote.connect(UPSTREAM)
        local.setblocking(False)
        remote.setblocking(False)
        print(f"Relay listening on {LISTEN[0]}:{LISTEN[1]} -> {UPSTREAM[0]}:{UPSTREAM[1]}", flush=True)
        print(f"Capture: {capture}; connectionless authentication packets excluded", flush=True)
        try:
            while not duration or time.monotonic() - started < duration:
                ready, _, _ = select.select([local, remote], [], [], 0.25)
                for current in ready:
                    try:
                        payload, sender = current.recvfrom(65535)
                    except (BlockingIOError, ConnectionResetError):
                        continue
                    if current is local:
                        if sender[0] != "127.0.0.1" and not sender[0].startswith("127."):
                            continue
                        if client is not None and sender != client:
                            # One game process only; a new ephemeral port may be
                            # accepted after inactivity, never during a session.
                            if time.monotonic() - last_client < 30:
                                continue
                        client = sender
                        last_client = time.monotonic()
                        remote.send(payload)
                        direction = "client_to_server"
                    else:
                        if not client:
                            continue
                        local.sendto(payload, client)
                        direction = "server_to_client"
                    stats[direction] += 1
                    record = capture_record(direction, payload)
                    if record is None:
                        stats["excluded"] += 1
                    else:
                        output.write(json.dumps(record, separators=(",", ":")) + "\n")
                        stats["recorded"] += 1
        except KeyboardInterrupt:
            pass
    print(json.dumps(stats), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, default=Path("artifacts/bootstrap/session.jsonl"))
    parser.add_argument("--duration", type=float, default=0, help="seconds; zero runs until Ctrl+C")
    args = parser.parse_args()
    try:
        run(args.capture, args.duration)
    except (OSError, ValueError) as error:
        parser.exit(1, f"relay failed: {error}\n")


if __name__ == "__main__":
    main()
