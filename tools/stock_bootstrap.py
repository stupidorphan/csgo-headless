"""Development-only stock demo bootstrap using Source's authenticated netconsole."""
import argparse
import json
from pathlib import Path
import secrets
import socket
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--game", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=30)
    parser.add_argument("--demo", default="codex_headless_bootstrap")
    args = parser.parse_args()
    if not args.demo.replace("_", "").isalnum():
        parser.error("demo must contain letters, digits, or underscores")
    password = secrets.token_hex(24)
    startup = subprocess.STARTUPINFO()
    startup.dwFlags = subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    process = subprocess.Popen([
        str(args.game / "csgo.exe"), "-steam", "-insecure", "-novid",
        "-windowed", "-w", "960", "-h", "540", "-console", "-condebug",
        "-netconport", "27017", "-netconpassword", password,
    ], cwd=args.game, startupinfo=startup)
    connection = None
    try:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("stock launcher exited before netconsole became available")
            try:
                connection = socket.create_connection(("127.0.0.1", 27017), timeout=1)
                break
            except OSError:
                time.sleep(1)
        if connection is None:
            raise RuntimeError("stock netconsole did not become available")
        connection.settimeout(0.1)
        connection.sendall(f"PASS {password}\nconnect 127.0.0.2:27016; record {args.demo}\n".encode())
        received = b""
        in_game = False
        demo = args.game / "csgo" / (args.demo + ".dem")
        retry_record = time.monotonic() + 1
        while time.monotonic() < deadline:
            if time.monotonic() >= retry_record:
                connection.sendall(f"record {args.demo}\n".encode())
                retry_record = time.monotonic() + 1
            try:
                data = connection.recv(65536)
                if not data:
                    raise RuntimeError("stock netconsole closed during signon")
                received = (received + data)[-131072:]
                if b"STEAM validation rejected" in received:
                    raise RuntimeError("server rejected stock Steam authentication")
                if b"LOADINGSCREEN -> CSGO_GAME_UI_STATE_INGAME" in received or b"LOADINGSCREEN -> INGAME" in received:
                    in_game = True
                if in_game and b"Recording to " in received:
                    break
            except socket.timeout:
                pass
        else:
            raise RuntimeError("stock client did not produce a demo during signon")
        print(json.dumps({"type": "stock_recording", "seconds": args.seconds}), flush=True)
        end = time.monotonic() + args.seconds
        while time.monotonic() < end:
            try:
                connection.recv(65536)
            except socket.timeout:
                pass
        connection.sendall(b"stop\ndisconnect\n")
        time.sleep(2)
        demo = args.game / "csgo" / (args.demo + ".dem")
        if not demo.is_file():
            raise RuntimeError("stock did not produce the requested demo")
        print(json.dumps({"type": "stock_demo", "path": str(demo), "bytes": demo.stat().st_size}), flush=True)
        connection.sendall(b"quit\n")
        process.wait(timeout=15)
    finally:
        if connection is not None:
            if process.poll() is None:
                try:
                    connection.sendall(b"stop\ndisconnect\nquit\n")
                    process.wait(timeout=15)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            connection.close()
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)


if __name__ == "__main__":
    main()
