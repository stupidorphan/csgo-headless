"""Drive the client through JSON stdio and print server-confirmed state."""
import argparse
import json
from pathlib import Path
import queue
import subprocess
import threading
import time

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--profile", type=Path, default=Path("profiles/legacy_13881.json"))
    args = parser.parse_args()
    process = subprocess.Popen([str(args.executable.resolve()), "--json", "--profile", str(args.profile.resolve())],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    incoming = queue.Queue()
    def read():
        for line in process.stdout:
            incoming.put(json.loads(line))
        incoming.put(None)
    threading.Thread(target=read, daemon=True).start()
    sequence = 0
    def request(op, timeout=45, **parameters):
        nonlocal sequence
        sequence += 1
        request_id = sequence
        process.stdin.write(json.dumps({"id": request_id, "op": op, "args": parameters}) + "\n")
        process.stdin.flush()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                message = incoming.get(timeout=min(1, max(0.01, deadline - time.monotonic())))
            except queue.Empty:
                continue
            if message is None:
                raise RuntimeError("Client stdout closed")
            if message.get("type") == "error":
                raise RuntimeError(message["message"])
            if message.get("id") == request_id:
                if not message.get("ok"):
                    raise RuntimeError(message["error"])
                return message["result"]
            print(json.dumps(message))
        raise TimeoutError(op + " response timed out")

    def wait_status(predicate, timeout, description):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = request("status")
            if predicate(status):
                return status
            if status.get("connection", {}).get("state") == "disconnected":
                raise RuntimeError(status["connection"].get("last_error") or "Disconnected")
            time.sleep(0.25)
        raise TimeoutError(description + " timed out")
    try:
        request("connect")
        wait_status(lambda state: state["connection"]["signon"] == 6, 120, "FULL signon")
        request("team", team="T")
        status = wait_status(lambda state: (state.get("local") or {}).get("health", 0) > 0, 180, "Spawn")
        print(json.dumps({"spawn": status["local"]}))
        request("input", forward=0.5, pitch=0, yaw=90, duration_ticks=32)
        time.sleep(1)
        print(json.dumps({"server_confirmed_status": request("status")}))
    finally:
        if process.poll() is None:
            try:
                request("quit", timeout=10)
                process.wait(timeout=10)
            except (OSError, RuntimeError, TimeoutError, subprocess.TimeoutExpired):
                process.stdin.close()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait(timeout=10)

if __name__ == "__main__":
    main()
