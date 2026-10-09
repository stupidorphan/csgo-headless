"""Operator-run live validation, restricted to the explicitly approved server.

No connection is made on import or with --self-test. Accepted command responses
are logged separately from evidence returned by the server. Unobservable actions
remain unverified; they are never counted as passed by inference.
"""
from __future__ import annotations

import argparse
from collections import deque
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time

SERVER = "151.243.93.16:27015"
GAME_DIRECTORY = Path(r"D:\SteamLibrary\steamapps\common\Counter-Strike Global Offensive")


def emit(kind, **data):
    print(json.dumps({"type": kind, **data}, separators=(",", ":")), flush=True)


def soak_input(step):
    """A fixed four-direction operator script; no gameplay decisions."""
    return {"forward": 0.35, "pitch": 0, "yaw": (0, 90, 180, -90)[step % 4],
            "buttons": [], "duration_ticks": 32}


def field(status, name, default=None):
    fields = (status.get("local") or {}).get("fields", {})
    for key, value in fields.items():
        if key == name or key.endswith("." + name):
            return value
    return default


def position(status):
    value = (status.get("local") or {}).get("position")
    if not isinstance(value, list) or len(value) != 3:
        return None
    if any(not isinstance(x, (int, float)) or not math.isfinite(x) for x in value):
        return None
    return value


def distance(a, b):
    return math.dist(a, b) if a is not None and b is not None else 0.0


def eye_angles(status):
    both = field(status, "m_angEyeAngles")
    if isinstance(both, list) and len(both) >= 2 and all(isinstance(x, (int, float)) and math.isfinite(x) for x in both[:2]):
        return both[:2]
    pitch, yaw = field(status, "m_angEyeAngles[0]"), field(status, "m_angEyeAngles[1]")
    return [pitch, yaw] if isinstance(pitch, (int, float)) and isinstance(yaw, (int, float)) else None


def alive(status):
    local = status.get("local") or {}
    health = local.get("health")
    return isinstance(health, (int, float)) and health > 0 and local.get("life_state") == 0


def active_weapon(status):
    local = status.get("local") or {}
    handle = local.get("active_weapon_handle")
    if not isinstance(handle, int):
        return None
    return next((item for item in local.get("inventory", []) if item.get("handle") == handle), None)


def gun_with_ammo(status):
    inventory = (status.get("local") or {}).get("inventory", [])
    current = active_weapon(status)
    if current and isinstance(current.get("clip"), int) and current["clip"] > 0:
        return current
    return next((item for item in inventory if isinstance(item.get("clip"), int) and item["clip"] > 0), None)


def magazine_changed(before, after, direction):
    first, last = active_weapon(before), active_weapon(after)
    if first is None or last is None or first.get("handle") != last.get("handle"):
        return False
    a, b = first.get("clip"), last.get("clip")
    if not isinstance(a, int) or not isinstance(b, int) or min(a, b) < 0:
        return False
    return b < a if direction == "decrease" else b > a


def compact(status):
    local = status.get("local") or {}
    return {"connection": status.get("connection", {}), "tick": status.get("tick"),
            "entity_tick": status.get("entity_tick"), "map": status.get("map"),
            "entity_count": status.get("entity_count"), "needs_full_update": status.get("needs_full_update"),
            "local": {**{key: local.get(key) for key in ("entity_index", "user_id", "team", "health",
                     "life_state", "position", "armor", "money", "active_weapon_handle", "inventory")},
                      "eye_angles": eye_angles(status), "duck_amount": field(status, "m_flDuckAmount")},
            "round": status.get("round", {})}


def contains_text(value, needle):
    if isinstance(value, str):
        return needle in value
    if isinstance(value, list):
        return any(contains_text(item, needle) for item in value)
    if isinstance(value, dict):
        encoded = value.get("hex")
        if isinstance(encoded, str):
            try:
                if needle in bytes.fromhex(encoded).decode("utf-8", errors="replace"):
                    return True
            except ValueError:
                pass
        return any(contains_text(item, needle) for key, item in value.items() if key != "hex")
    return False


def inspect_processes(pid=None):
    """Read stock process names and client/helper DLLs. This is not a file-I/O audit."""
    if os.name != "nt":
        return {"verified": False, "reason": "Windows process inspection unavailable", "asset_file_reads_checked": False}
    script = "$stock=@(Get-Process csgo,cs2 -ErrorAction SilentlyContinue | Select-Object Id,ProcessName);"
    if pid is None:
        script += "@{stock=$stock;processes=@()} | ConvertTo-Json -Depth 5 -Compress"
    else:
        script += (
            f"$ids=@({int(pid)})+@(Get-CimInstance Win32_Process -Filter 'ParentProcessId = {int(pid)}' | Select-Object -ExpandProperty ProcessId);"
            "$rows=@(foreach($processId in $ids){$p=Get-Process -Id $processId -ErrorAction Stop;"
            "@{id=$p.Id;name=$p.ProcessName;modules=@($p.Modules | Select-Object -ExpandProperty FileName)}});"
            "@{stock=$stock;processes=$rows} | ConvertTo-Json -Depth 6 -Compress"
        )
    completed = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                               capture_output=True, text=True, timeout=20, check=False)
    if completed.returncode:
        return {"verified": False, "reason": completed.stderr.strip(), "asset_file_reads_checked": False}
    result = json.loads(completed.stdout)
    result["verified"] = True
    result["asset_file_reads_checked"] = False
    banned = {"engine.dll", "client.dll", "client_panorama.dll", "materialsystem.dll", "server.dll"}
    game_prefix = str(GAME_DIRECTORY).casefold() + "\\"
    result["forbidden_modules"] = [path for process in result.get("processes", [])
                                   for path in process.get("modules", [])
                                   if Path(path).name.casefold() in banned or path.casefold().startswith(game_prefix)]
    return result


class Driver:
    def __init__(self, executable, profile, directory, trace=False):
        self.started = time.monotonic()
        self.queue = queue.Queue()
        self.events = deque(maxlen=20000)
        self.event_number = 0
        self.responses = {}
        self.sequence = 0
        self.fatal = None
        self.full = False
        self.closing = False
        self.lock = threading.Lock()
        self.log = (directory / "client.jsonl").open("w", encoding="utf-8")
        self.stderr = (directory / "stderr.log").open("w", encoding="utf-8")
        command = [str(executable), "--json", "--profile", str(profile), "--server", SERVER, "--name", "headless-validation"]
        if trace:
            command.append("--trace")
        startup = None
        if os.name == "nt":
            startup = subprocess.STARTUPINFO()
            startup.dwFlags = subprocess.STARTF_USESHOWWINDOW
            startup.wShowWindow = 0
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr,
                                        text=True, encoding="utf-8", errors="replace", bufsize=1,
                                        cwd=executable.parent, startupinfo=startup)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def record(self, direction, value):
        with self.lock:
            self.log.write(json.dumps({"elapsed_seconds": round(time.monotonic() - self.started, 3),
                                       "direction": direction, "message": value}, separators=(",", ":")) + "\n")
            self.log.flush()

    def _read(self):
        try:
            for line in self.process.stdout:
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                    if not isinstance(value, dict):
                        raise ValueError("stdout record is not an object")
                except (ValueError, json.JSONDecodeError) as error:
                    self.queue.put({"type": "harness_error", "message": f"Invalid client JSON: {error}"})
                    continue
                self.record("received", value)
                self.queue.put(value)
        finally:
            self.queue.put({"type": "stdout_closed"})

    def pump(self, timeout=0.0):
        try:
            value = self.queue.get(timeout=timeout)
        except queue.Empty:
            value = None
        if value:
            kind = value.get("type")
            if kind == "response":
                self.responses[value.get("id")] = value
            elif kind not in ("stdout_closed",):
                self.event_number += 1
                self.events.append((self.event_number, value))
            if kind in ("error", "harness_error") and not self.closing:
                self.fatal = value.get("message", str(value))
            if kind == "disconnected" and not self.closing:
                self.fatal = "Unexpected disconnect: " + str(value.get("reason"))
        if self.fatal:
            raise RuntimeError(self.fatal)
        if self.process.poll() is not None and not self.closing:
            raise RuntimeError(f"Client exited unexpectedly with code {self.process.returncode}")

    def request(self, op, timeout=15, **args):
        self.sequence += 1
        request = {"id": self.sequence, "op": op, "args": args}
        self.record("sent", request)
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        deadline = time.monotonic() + timeout
        while self.sequence not in self.responses:
            self.pump(min(0.2, max(0.0, deadline - time.monotonic())))
            if time.monotonic() >= deadline:
                raise TimeoutError(f"No response to {op}")
        response = self.responses.pop(self.sequence)
        if not response.get("ok"):
            raise RuntimeError(f"{op} rejected: {response.get('error')}")
        return response.get("result", {})

    def status(self):
        while not self.queue.empty():
            self.pump()
        status = self.request("status")
        connection = status.get("connection", {})
        if connection.get("last_error"):
            raise RuntimeError(connection["last_error"])
        if self.full and connection.get("signon") != 6:
            raise RuntimeError("Connection left FULL during validation")
        return status

    def wait(self, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.pump(min(0.2, deadline - time.monotonic()))

    def wait_status(self, predicate, seconds, label):
        deadline = time.monotonic() + seconds
        latest = {}
        while time.monotonic() < deadline:
            latest = self.status()
            if predicate(latest):
                return latest
            self.wait(0.1)
        raise TimeoutError(f"No server-confirmed {label}; latest={json.dumps(compact(latest))}")

    def wait_auth(self, seconds=300):
        deadline = time.monotonic() + seconds
        latest = {}
        while time.monotonic() < deadline:
            latest = self.request("auth_status", timeout=45)
            if latest.get("state") == "authenticated":
                return latest
            if latest.get("state") in {"token_error", "cm_error", "signed_out"}:
                raise RuntimeError("Steam authentication failed: " + latest.get("state", "unknown"))
            self.wait(1)
        raise TimeoutError(f"Steam authentication did not complete; latest={json.dumps(latest)}")

    def event(self, after, names, user_id=None):
        for number, value in reversed(self.events):
            if number <= after:
                break
            if value.get("type") != "game_event" or value.get("name") not in names:
                continue
            actor = value.get("values", {}).get("userid")
            if user_id is not None and (actor is None or str(actor) != str(user_id)):
                continue
            return value
        return None

    def close(self):
        self.closing = True
        try:
            if self.process.poll() is None:
                try:
                    self.request("quit", timeout=5)
                except (OSError, RuntimeError, TimeoutError):
                    pass
                self.process.stdin.close()
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.process.terminate()
                    self.process.wait(timeout=5)
        finally:
            self.reader.join(timeout=3)
            self.log.close()
            self.stderr.close()


def exercise(driver, report):
    results = report["controls"]

    def attempt(name, op, parameters, predicate, timeout=5, event_names=(), reason="No qualifying server state or event was observed", neutralize=True, event_match=None, event_validator=None):
        before = driver.status()
        after_event = driver.event_number
        user_id = (before.get("local") or {}).get("user_id")
        accepted = driver.request(op, **parameters)
        deadline = time.monotonic() + timeout
        latest = before
        event = None
        verified = False
        while time.monotonic() < deadline:
            latest = driver.status()
            event = driver.event(after_event, set(event_names), user_id)
            if event is not None and event_validator is not None and not event_validator(before, latest, event):
                event = None
            if event is None and event_match is not None:
                event = next((value for number, value in reversed(driver.events)
                              if number > after_event and event_match(value)), None)
            if predicate(before, latest) or event:
                verified = True
                break
            driver.wait(0.05)
        result = {"state": "verified" if verified else "not_observed", "accepted_response": accepted,
                  "before": compact(before), "after": compact(latest)}
        if event:
            result["server_event"] = event
        if not verified:
            result["reason"] = reason
        results[name] = result
        emit("control", name=name, state=result["state"])
        # A new input replaces the prior duration/button state; end each action
        # neutrally even when evidence was found before its duration expired.
        if op == "input" and neutralize:
            driver.request("input", duration_ticks=1, buttons=[])
            driver.wait(0.2)
        return latest

    # Health may arrive before the separate weapon entities at a round start.
    # Give those authoritative inventory snapshots a bounded chance to settle.
    spawned = driver.status()
    inventory_deadline = time.monotonic() + 5
    while time.monotonic() < inventory_deadline and (not alive(spawned) or active_weapon(spawned) is None):
        driver.wait(0.1)
        spawned = driver.status()
    report["spawn"] = compact(spawned)
    inventory = (spawned.get("local") or {}).get("inventory", [])
    results["inventory"] = {"state": "verified" if inventory else "not_observed", "server_inventory": inventory}

    # With the stock cl_use_opens_buy_menu=1 userinfo, +use in a buy zone
    # makes the server send NET_StringCmd("buymenu"). The receipt proves
    # server-side input handling without requiring a conveniently placed door.
    attempt("use", "input", {"buttons": ["use"], "duration_ticks": 2},
            lambda a, b: field(b, "m_hUseEntity") is not None and field(b, "m_hUseEntity") != field(a, "m_hUseEntity"),
            event_names=("player_use", "hostage_follows"), timeout=3,
            event_match=lambda value: value.get("type") == "server_command" and value.get("command", "").strip() == "buymenu",
            reason="No server buy-menu command or usable target was demonstrated at spawn")

    attempt("buy", "buy", {"item": "vest"},
            lambda a, b: (b.get("local") or {}).get("armor", 0) > (a.get("local") or {}).get("armor", 0),
            event_names=("item_purchase",), reason="Purchase not confirmed; buy zone, money, or buy time may prevent it")
    before_weapon = driver.status()
    inventory = (before_weapon.get("local") or {}).get("inventory", [])
    active = active_weapon(before_weapon)
    different = next((item for item in inventory if item.get("handle") != (active or {}).get("handle")), None)
    if different:
        attempt("weapon", "weapon", {"entity": different["entity_index"]},
                lambda a, b: (b.get("local") or {}).get("active_weapon_handle") == different["handle"])
    else:
        results["weapon"] = {"state": "not_observed", "reason": "No second server-reported weapon available for a measurable switch"}
    initial_angles = eye_angles(driver.status())
    aim_pitch = -12 if initial_angles and abs(initial_angles[0] - 12) < 6 else 12
    aim_yaw = math.remainder(initial_angles[1] + 37, 360) if initial_angles else 40
    attempt("aim", "input", {"pitch": aim_pitch, "yaw": aim_yaw, "duration_ticks": 1},
            lambda a, b: eye_angles(b) is not None and abs(eye_angles(b)[0] - aim_pitch) < 3 and
                         abs(math.remainder(eye_angles(b)[1] - aim_yaw, 360)) < 3,
            reason="Local eye-angle properties were unavailable or did not confirm the requested angles")
    movement = attempt("movement", "input", {"forward": 0.7, "pitch": 0, "yaw": 0, "duration_ticks": 32},
            lambda a, b: alive(b) and distance(position(a), position(b)) > 4,
            reason="No movement larger than four Source units was confirmed", neutralize=False)
    # Do not send a replacement input until after checking automatic expiry.
    interval = movement.get("tick_interval", 1 / 64)
    interval = interval if isinstance(interval, (int, float)) and 0 < interval <= 0.1 else 1 / 64
    driver.wait(32 * interval + 0.5)
    stopped_a = driver.status()
    driver.wait(0.5)
    stopped_b = driver.status()
    stopped = results["movement"]["state"] == "verified" and alive(stopped_b) and position(stopped_a) is not None and position(stopped_b) is not None and distance(position(stopped_a), position(stopped_b)) < 1
    results["input_expiry"] = {"state": "verified" if stopped else "not_observed", "positions": [position(stopped_a), position(stopped_b)],
                               "reason": "Position stability after input expiry; environmental motion can prevent this check"}
    driver.request("input", duration_ticks=1, buttons=[])

    attempt("jump", "input", {"buttons": ["jump"], "duration_ticks": 8},
            lambda a, b: position(a) is not None and position(b) is not None and position(b)[2] - position(a)[2] > 5,
            event_names=("player_jump",), timeout=3)
    driver.wait(0.8)
    attempt("crouch", "input", {"buttons": ["duck"], "duration_ticks": 48},
            lambda a, b: isinstance(field(b, "m_flDuckAmount"), (int, float)) and
                         isinstance(field(a, "m_flDuckAmount", 0), (int, float)) and
                         field(b, "m_flDuckAmount") > field(a, "m_flDuckAmount", 0) + 0.1,
            reason="Server duck amount did not increase")

    # Refresh after movement/round changes instead of selecting a stale weapon
    # from the spawn inventory. Missing selection evidence must not abort soak.
    before_gun = driver.status()
    gun = gun_with_ammo(before_gun)
    gun_state = before_gun
    accepted = None
    if gun and (before_gun.get("local") or {}).get("active_weapon_handle") != gun["handle"]:
        accepted = driver.request("weapon", entity=gun["entity_index"])
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            gun_state = driver.status()
            if (gun_state.get("local") or {}).get("active_weapon_handle") == gun["handle"]:
                break
            driver.wait(0.1)
    # Equipping is replicated before the server permits attacks. Source's
    # DefaultDeploy sets the owner's next attack to the draw animation end.
    # Allow a bounded draw delay; firing still needs a real server effect.
    deployment_started = time.monotonic()
    driver.wait(1.5)
    gun_state = driver.status()
    deployment_wait = time.monotonic() - deployment_started
    selected_gun = active_weapon(gun_state)
    gun_ready = alive(gun_state) and selected_gun is not None and isinstance(selected_gun.get("clip"), int) and selected_gun["clip"] > 0
    report["gun_preparation"] = {"state": "verified" if gun_ready else "not_observed", "accepted_response": accepted,
                                 "before": compact(before_gun), "after": compact(gun_state),
                                 "deployment_wait_seconds": round(deployment_wait, 3),
                                 "next_attack": field(gun_state, "m_flNextAttack"),
                                 "reason": None if gun_ready else "No active server-reported gun with ammunition was confirmed"}
    attempt("fire", "input", {"buttons": ["attack"], "duration_ticks": 16},
            lambda a, b: magazine_changed(a, b, "decrease"), event_names=("weapon_fire",),
            event_validator=lambda a, b, event: alive(a) and gun_with_ammo(a) == active_weapon(a) and active_weapon(a) is not None and
                bool(event.get("values", {}).get("weapon")) and event["values"]["weapon"] not in ("knife", "knife_t", "knifegg", "bayonet", "c4"),
            reason="No weapon-fire event or authoritative magazine decrease was observed")
    attempt("reload", "input", {"buttons": ["reload"], "duration_ticks": 1},
            lambda a, b: magazine_changed(a, b, "increase"), event_names=("weapon_reload",), timeout=8)
    if results["use"]["state"] != "verified":
        attempt("use", "input", {"buttons": ["use"], "duration_ticks": 4},
                lambda a, b: field(b, "m_hUseEntity") is not None and field(b, "m_hUseEntity") != field(a, "m_hUseEntity"),
                event_names=("player_use", "hostage_follows"), timeout=3,
                event_match=lambda value: value.get("type") == "server_command" and value.get("command", "").strip() == "buymenu",
                reason="No server buy-menu command or usable target was demonstrated at the current position")

    for operation in ("say", "say_team"):
        # Source shares a 0.66-second TALK_INTERVAL between both commands.
        # Allow 1.5 seconds for server scheduling and custom server extensions.
        driver.wait(1.5)
        token = "headless validation " + operation + " " + str(time.time_ns())
        after_event = driver.event_number
        accepted = driver.request(operation, text=token)
        deadline = time.monotonic() + 5
        echo = None
        while time.monotonic() < deadline:
            driver.pump(0.1)
            echo = next((value for number, value in reversed(driver.events) if number > after_event and
                         value.get("type") == "user_message" and contains_text(value, token)), None)
            if echo:
                break
        results[operation] = {"state": "verified" if echo else "not_observed", "accepted_response": accepted,
                              "server_echo": echo, "reason": None if echo else "No matching server chat echo observed"}
        emit("control", name=operation, state=results[operation]["state"])


def self_test():
    assert [soak_input(step)["yaw"] for step in range(5)] == [0, 90, 180, -90, 0]
    assert all(soak_input(step)["duration_ticks"] == 32 and not soak_input(step)["buttons"] for step in range(5))
    assert position({"local": {"position": [1, 2, 3]}}) == [1, 2, 3]
    assert position({"local": {"position": [None, 2, 3]}}) is None
    assert not distance(None, [1, 2, 3])
    assert alive({"local": {"health": 100, "life_state": 0}})
    assert not alive({"local": {"health": 0, "life_state": 1}})
    assert contains_text({"fields": [{"hex": "68656c6c6f"}]}, "hello")
    assert not contains_text({"accepted": True}, "hello")
    assert eye_angles({"local": {"fields": {"DT_Player.m_angEyeAngles[0]": 12, "DT_Player.m_angEyeAngles[1]": 40}}}) == [12, 40]
    assert active_weapon({"local": {"active_weapon_handle": 23, "inventory": [{"handle": 23, "clip": 12}]}})["clip"] == 12
    a = {"local": {"active_weapon_handle": 23, "inventory": [{"handle": 23, "clip": 12}]}}
    b = {"local": {"active_weapon_handle": 23, "inventory": [{"handle": 23, "clip": 11}]}}
    switched = {"local": {"active_weapon_handle": 24, "inventory": [{"handle": 24, "clip": 1}]}}
    assert magazine_changed(a, b, "decrease") and not magazine_changed(a, switched, "decrease")
    assert gun_with_ammo(a)["handle"] == 23 and gun_with_ammo({"local": {"inventory": []}}) is None
    emit("self_test", ok=True, network_used=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", nargs="?", type=Path, default=Path("build/Release/headless-csgo.exe"))
    parser.add_argument("--profile", type=Path, default=Path("profiles/legacy_13881.json"))
    parser.add_argument("--server", default=SERVER, choices=[SERVER])
    parser.add_argument("--seconds", type=int, default=1800, help="Continuous FULL soak after controls, default 30 minutes")
    parser.add_argument("--activity-seconds", type=int, default=30,
                        help="Repeat a fixed movement/view script during soak; 0 requests an idle soak")
    parser.add_argument("--connect-only", action="store_true", help="Check FULL and soak without gameplay")
    parser.add_argument("--connect-timeout", type=int, default=150)
    parser.add_argument("--spawn-timeout", type=int, default=180)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--trace", action="store_true")
    parser.add_argument("--auth-qr", action="store_true", help="Start an in-process QR login and wait for the operator to approve it")
    parser.add_argument("--skip-module-check", action="store_true", help="Report DLL/stock process verification as unverified")
    parser.add_argument("--self-test", action="store_true", help="Run offline harness checks without launching the client")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.seconds < 1 or args.seconds > 86400 or args.connect_timeout < 1 or args.spawn_timeout < 1 or not 0 <= args.activity_seconds <= 300:
        parser.error("Durations must be positive; soak must be at most 86400 seconds")
    executable, profile = args.executable.resolve(), args.profile.resolve()
    if not executable.is_file() or not profile.is_file():
        parser.error("Executable and metadata profile must exist")
    directory = (args.output or Path("artifacts/live") / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    report = {"server": SERVER, "executable": str(executable), "profile": str(profile),
              "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
              "profile_sha256": hashlib.sha256(profile.read_bytes()).hexdigest(),
              "started_at": datetime.now(timezone.utc).isoformat(), "requested_soak_seconds": args.seconds,
              "connect_only": args.connect_only, "controls": {}, "state": "running"}
    driver = None
    soak_started = None
    started = time.monotonic()
    try:
        if not args.skip_module_check:
            report["runtime_before"] = inspect_processes()
            if not report["runtime_before"].get("verified"):
                raise RuntimeError("Stock process inspection could not be verified")
            if report["runtime_before"].get("stock"):
                raise RuntimeError("Stock CS:GO/CS2 is running; close it before standalone validation")
        driver = Driver(executable, profile, directory, args.trace)
        if args.auth_qr:
            driver.request("auth", timeout=30, mode="qr")
            emit("auth_wait", message="Approve the QR challenge shown in the auth_qr event")
            driver.wait_auth(300)
        driver.request("connect", timeout=45)
        status = driver.wait_status(lambda value: value.get("connection", {}).get("signon") == 6,
                                   args.connect_timeout, "FULL signon")
        driver.full = True
        report["full_signon"] = compact(status)
        report["full_elapsed_seconds"] = round(time.monotonic() - started, 3)
        emit("full", status=compact(status), report=str(directory / "validation.json"))
        if not args.skip_module_check:
            report["runtime_full"] = inspect_processes(driver.process.pid)
            runtime = report["runtime_full"]
            if not runtime.get("verified") or runtime.get("stock") or runtime.get("forbidden_modules"):
                raise RuntimeError("Standalone module/stock-process verification failed")
        else:
            report["runtime_full"] = {"verified": False, "reason": "Operator skipped module inspection", "asset_file_reads_checked": False}
        if not args.connect_only:
            driver.request("team", team="T")
            status = driver.wait_status(lambda value: (value.get("local") or {}).get("team") == 2, 30, "T team")
            report["team"] = compact(status)
            status = driver.wait_status(alive, args.spawn_timeout, "alive player spawn")
            # An empty server restarts the round after its first player joins.
            driver.wait(7)
            status = driver.wait_status(lambda value: alive(value) and not value.get("round", {}).get("freeze", 0), 30, "spawn after freeze time")
            exercise(driver, report)
        soak_started = time.monotonic()
        initial = driver.status()
        measurements = []
        activity = []
        report["soak"] = {"initial": compact(initial), "measurements": measurements, "continuous_full": False,
                          "activity_interval_seconds": args.activity_seconds, "activity": activity}
        deadline = soak_started + args.seconds
        next_status = soak_started
        next_activity = soak_started if args.activity_seconds else deadline
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now >= next_status:
                status = driver.status()
                measurement = {"elapsed_seconds": round(now - soak_started, 3), **compact(status)}
                measurements.append(measurement)
                emit("soak", elapsed_seconds=measurement["elapsed_seconds"], tick=status.get("tick"),
                     received_packets=status.get("connection", {}).get("received_packets"),
                     health=(status.get("local") or {}).get("health"))
                if len(measurements) > 1 and status.get("connection", {}).get("received_packets", 0) <= measurements[-2]["connection"].get("received_packets", 0):
                    raise RuntimeError("No received packet progress between soak measurements")
                next_status += 30
            if now >= next_activity:
                command = soak_input(len(activity))
                accepted = driver.request("input", **command)
                activity.append({"elapsed_seconds": round(time.monotonic() - soak_started, 3),
                                 "input": command, "accepted_response": accepted})
                next_activity += args.activity_seconds
            driver.wait(min(0.2, max(0.0, deadline - time.monotonic())))
        final = driver.status()
        if final.get("tick", 0) <= initial.get("tick", 0) or final.get("connection", {}).get("received_packets", 0) <= initial.get("connection", {}).get("received_packets", 0):
            raise RuntimeError("Server tick or received packets did not advance during soak")
        report["soak"] = {"elapsed_seconds": round(time.monotonic() - soak_started, 3), "measurements": measurements,
                           "initial": compact(initial), "final": compact(final), "continuous_full": True,
                           "activity_interval_seconds": args.activity_seconds, "activity": activity}
        if not args.skip_module_check:
            report["runtime_end"] = inspect_processes(driver.process.pid)
            runtime = report["runtime_end"]
            if not runtime.get("verified") or runtime.get("stock") or runtime.get("forbidden_modules"):
                raise RuntimeError("Standalone runtime verification failed at soak completion")
        unverified = [name for name, result in report["controls"].items() if result["state"] != "verified"]
        report["unverified_controls"] = unverified
        report["state"] = "connection_verified" if args.connect_only else ("verified" if not unverified else "incomplete")
        report["thirty_minute_soak_verified"] = report["soak"]["elapsed_seconds"] >= 1800
    except KeyboardInterrupt:
        report["state"] = "interrupted"
        report["error"] = "Operator interrupted validation"
    except (OSError, ValueError, RuntimeError, TimeoutError, subprocess.SubprocessError) as error:
        report["state"] = "failed"
        report["error"] = str(error)
        emit("failure", message=str(error))
    finally:
        if driver:
            try:
                driver.close()
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                report["cleanup_error"] = str(error)
                report["state"] = "failed"
        if soak_started is not None and "elapsed_seconds" not in report.get("soak", {}):
            report["soak"]["elapsed_seconds"] = round(time.monotonic() - soak_started, 3)
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        (directory / "validation.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        emit("validation_complete", state=report["state"], elapsed_seconds=report["elapsed_seconds"], report=str(directory / "validation.json"),
             unverified_controls=report.get("unverified_controls", []))
    return 0 if report["state"] in ("verified", "connection_verified") else 1


if __name__ == "__main__":
    raise SystemExit(main())
