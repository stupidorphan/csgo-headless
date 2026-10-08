"""Minimal controller: genuine Steam session, JSON stdio, server-confirmed state."""
import argparse
import json
import queue
import subprocess
import threading
import time

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("executable")
    parser.add_argument("--profile", default="profiles/legacy_13881.json")
    args = parser.parse_args()
    process = subprocess.Popen([args.executable, "--json", "--profile", args.profile],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    events = queue.Queue()
    def read():
        for line in process.stdout:
            events.put(json.loads(line))
    threading.Thread(target=read, daemon=True).start()
    sequence = 0
    def send(op, **parameters):
        nonlocal sequence
        sequence += 1
        process.stdin.write(json.dumps({"id": sequence, "op": op, "args": parameters}) + "\n")
        process.stdin.flush()
    try:
        send("connect")
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            event = events.get(timeout=5)
            print(json.dumps(event))
            if event.get("type") == "error":
                raise RuntimeError(event["message"])
            if event.get("type") == "signon" and event.get("state") == 6:
                break
        else:
            raise TimeoutError("Full signon was not reached")
        send("team", team="T")
        time.sleep(5)
        send("input", forward=1, duration_ticks=32)
        time.sleep(1)
        send("status")
        time.sleep(1)
    finally:
        if process.poll() is None:
            send("quit")
            process.wait(timeout=10)

if __name__ == "__main__":
    main()
