"""Retain quantitative live evidence without identities, chat, paths, or raw fields.

This is an offline report converter. It never launches a client or connects to a
server. Input reports remain local; the allowlisted output can be committed.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path, PureWindowsPath
import re

SERVER = "151.243.93.16:27015"
CONTROLS = ("inventory", "use", "buy", "weapon", "aim", "movement", "input_expiry",
            "jump", "crouch", "fire", "reload", "say", "say_team")
STATES = {"running", "verified", "connection_verified", "incomplete", "failed", "interrupted", "not_observed"}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,127}\Z")


def number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def numeric_fields(value, names):
    value = value if isinstance(value, dict) else {}
    return {name: value[name] for name in names if number(value.get(name))}


def vector(value, length):
    return list(value) if isinstance(value, list) and len(value) == length and all(map(number, value)) else None


def inventory(value):
    result = []
    for item in value if isinstance(value, list) else []:
        if not isinstance(item, dict):
            continue
        entry = numeric_fields(item, ("entity_index", "handle", "serial", "item_definition", "clip"))
        if isinstance(item.get("class"), str) and IDENTIFIER.fullmatch(item["class"]):
            entry["class"] = item["class"]
        if entry:
            result.append(entry)
    return result


def snapshot(value):
    value = value if isinstance(value, dict) else {}
    result = numeric_fields(value, ("tick", "entity_tick", "entity_count", "elapsed_seconds"))
    if isinstance(value.get("map"), str) and IDENTIFIER.fullmatch(value["map"]):
        result["map"] = value["map"]
    if isinstance(value.get("needs_full_update"), bool):
        result["needs_full_update"] = value["needs_full_update"]
    connection = value.get("connection", {})
    result["connection"] = numeric_fields(connection, ("signon", "tick", "received_packets", "sent_packets"))
    if isinstance(connection, dict) and connection.get("state") in {
            "disconnected", "challenge", "connected", "new", "prespawn", "spawn", "full",
            "NONE", "CHALLENGE", "CONNECTED", "NEW", "PRESPAWN", "SPAWN", "FULL"}:
        result["connection"]["state"] = connection["state"]
    local = value.get("local", {})
    result["local"] = numeric_fields(local, ("entity_index", "team", "health", "life_state", "armor", "money",
                                               "active_weapon_handle", "duck_amount"))
    if isinstance(local, dict):
        for name, length in (("position", 3), ("eye_angles", 2)):
            candidate = vector(local.get(name), length)
            if candidate is not None:
                result["local"][name] = candidate
        result["local"]["inventory"] = inventory(local.get("inventory"))
    round_state = value.get("round", {})
    result["round"] = numeric_fields(round_state, ("rounds_played", "freeze", "round_time", "start_time",
                                                   "start_tick", "freeze_end_tick", "warmup"))
    if isinstance(round_state, dict) and round_state.get("phase") in {"active", "freeze", "warmup", "ended"}:
        result["round"]["phase"] = round_state["phase"]
    return result


def server_event(value):
    value = value if isinstance(value, dict) else {}
    result = numeric_fields(value, ("tick", "event_id"))
    if value.get("type") in {"game_event", "server_command"}:
        result["type"] = value["type"]
    if isinstance(value.get("name"), str) and value["name"] in {
            "item_purchase", "player_jump", "weapon_fire", "weapon_reload", "player_use", "hostage_follows"}:
        result["name"] = value["name"]
    if value.get("type") == "server_command":
        result["buy_menu_observed"] = value.get("command", "").strip() == "buymenu" if isinstance(value.get("command"), str) else False
    values = value.get("values", {})
    safe_values = numeric_fields(values, ("team", "silenced", "weaponid", "itemid", "count"))
    if isinstance(values, dict):
        for key in ("weapon", "item"):
            if isinstance(values.get(key), str) and IDENTIFIER.fullmatch(values[key]):
                safe_values[key] = values[key]
        if isinstance(values.get("silenced"), bool):
            safe_values["silenced"] = values["silenced"]
    if safe_values:
        result["values"] = safe_values
    return result


def module_basename(path):
    if not isinstance(path, str):
        return None
    name = PureWindowsPath(path).name
    return name if name.casefold().endswith((".dll", ".exe")) else None


def activity(value):
    result = []
    for item in value if isinstance(value, list) else []:
        if not isinstance(item, dict):
            continue
        entry = numeric_fields(item, ("elapsed_seconds",))
        source = item.get("input", {})
        entry["input"] = numeric_fields(source, ("forward", "side", "up", "pitch", "yaw", "duration_ticks"))
        if isinstance(source, dict) and isinstance(source.get("buttons"), list):
            entry["input"]["buttons"] = [name for name in source["buttons"] if isinstance(name, str) and name in {
                "attack", "attack2", "jump", "duck", "use", "reload", "walk"}]
        result.append(entry)
    return result


def runtime(value, module_hashes):
    value = value if isinstance(value, dict) else {}
    result = {"verified": value.get("verified") is True,
              "asset_file_reads_checked": value.get("asset_file_reads_checked") is True,
              "stock_process_count": len(value.get("stock", [])) if isinstance(value.get("stock"), list) else 0}
    processes = []
    for process in value.get("processes", []) if isinstance(value.get("processes"), list) else []:
        if not isinstance(process, dict):
            continue
        name = process.get("name")
        if name not in ("headless-csgo",):
            name = "other"
        modules = {}
        for path in process.get("modules", []) if isinstance(process.get("modules"), list) else []:
            basename = module_basename(path)
            if basename:
                item = {"name": basename}
                if SHA256.fullmatch(module_hashes.get(path, "")):
                    item["sha256"] = module_hashes[path]
                modules[(basename.casefold(), item.get("sha256", ""))] = item
        processes.append({"name": name, "modules": [modules[key] for key in sorted(modules)]})
    result["processes"] = processes
    result["forbidden_module_count"] = len(value.get("forbidden_modules", [])) if isinstance(value.get("forbidden_modules"), list) else 0
    return result


def summarize(report, profile_sha256, module_hashes=None, failure_category=None):
    if not isinstance(report, dict) or report.get("server") != SERVER:
        raise ValueError("Input must describe the authorized validation endpoint")
    if not isinstance(profile_sha256, str) or not SHA256.fullmatch(profile_sha256):
        raise ValueError("A valid metadata profile SHA256 is required")
    binary_sha256 = report.get("executable_sha256", "")
    if not isinstance(binary_sha256, str) or not SHA256.fullmatch(binary_sha256):
        raise ValueError("Input must contain the tested binary SHA256")
    if "profile_sha256" in report and report["profile_sha256"] != profile_sha256:
        raise ValueError("Supplied metadata differs from the tested profile SHA256")
    result = {"format": 1, "host_version": 13881, "server": SERVER,
              "executable_sha256": binary_sha256, "profile_sha256": profile_sha256,
              "state": report.get("state") if report.get("state") in STATES else "unknown",
              "connect_only": report.get("connect_only") is True}
    result.update(numeric_fields(report, ("requested_soak_seconds", "elapsed_seconds", "full_elapsed_seconds")))
    for name in ("started_at", "finished_at"):
        value = report.get(name)
        if isinstance(value, str):
            try:
                stamp = datetime.fromisoformat(value)
                if stamp.tzinfo is not None:
                    result[name] = stamp.isoformat()
            except ValueError:
                pass
    for name in ("full_signon", "team", "spawn"):
        if isinstance(report.get(name), dict):
            result[name] = snapshot(report[name])
    result["controls"] = {}
    controls = report.get("controls", {})
    for name in CONTROLS:
        source = controls.get(name) if isinstance(controls, dict) else None
        if not isinstance(source, dict):
            continue
        target = {"state": source.get("state") if source.get("state") in STATES else "unknown"}
        for key in ("before", "after"):
            if isinstance(source.get(key), dict):
                target[key] = snapshot(source[key])
        if "server_inventory" in source:
            target["server_inventory"] = inventory(source["server_inventory"])
        if isinstance(source.get("positions"), list):
            target["positions"] = [position for item in source["positions"] if (position := vector(item, 3)) is not None]
        if isinstance(source.get("server_event"), dict):
            target["server_event"] = server_event(source["server_event"])
        if name in ("say", "say_team"):
            target["echo_verified"] = source.get("state") == "verified" and isinstance(source.get("server_echo"), dict)
        result["controls"][name] = target
    result["unverified_controls"] = [name for name in CONTROLS if result["controls"].get(name, {}).get("state") != "verified"]
    gun = report.get("gun_preparation")
    if isinstance(gun, dict):
        result["gun_preparation"] = numeric_fields(gun, ("deployment_wait_seconds", "next_attack"))
        result["gun_preparation"]["state"] = gun.get("state") if gun.get("state") in STATES else "unknown"
    soak = report.get("soak", {})
    soak = soak if isinstance(soak, dict) else {}
    result["soak"] = numeric_fields(soak, ("elapsed_seconds", "activity_interval_seconds"))
    result["soak"]["continuous_full"] = soak.get("continuous_full") is True
    for name in ("initial", "final"):
        if isinstance(soak.get(name), dict):
            result["soak"][name] = snapshot(soak[name])
    result["soak"]["measurements"] = [snapshot(item) for item in soak.get("measurements", []) if isinstance(item, dict)] if isinstance(soak.get("measurements"), list) else []
    if "activity" in soak:
        result["soak"]["activity"] = activity(soak["activity"])
    result["thirty_minute_soak_verified"] = (result["soak"]["continuous_full"] and
                                             result["soak"].get("elapsed_seconds", 0) >= 1800)
    if "error" in report:
        result["error_present"] = bool(report["error"])
    if failure_category in {"server_afk_rejection", "unexpected_disconnect", "timeout", "other"}:
        result["failure_category"] = failure_category
    if "cleanup_error" in report:
        result["cleanup_error_present"] = bool(report["cleanup_error"])
    for name in ("runtime_before", "runtime_full", "runtime_end"):
        if isinstance(report.get(name), dict):
            result[name] = runtime(report[name], module_hashes or {})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--profile", type=Path, default=Path(__file__).resolve().parents[1] / "profiles/legacy_13881.json",
                        help="Matching derived metadata profile (defaults to the supplied Legacy profile)")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--failure-category", choices=("server_afk_rejection", "unexpected_disconnect", "timeout", "other"),
                        help="Optional operator-reviewed category; raw diagnostic text is never copied")
    args = parser.parse_args()
    source = args.input.read_bytes()
    report = json.loads(source)
    profile = args.profile.read_bytes()
    metadata = json.loads(profile)
    if metadata.get("host_version") != 13881 or metadata.get("integrity", {}).get("coverage", {}).get("server") != SERVER:
        parser.error("Metadata must match host 13881 and the authorized endpoint")
    module_hashes = {}
    for name in ("runtime_before", "runtime_full", "runtime_end"):
        for process in report.get(name, {}).get("processes", []):
            for path in process.get("modules", []):
                if module_basename(path):
                    try:
                        module_hashes[path] = hashlib.sha256(Path(path).read_bytes()).hexdigest()
                    except OSError:
                        pass
    result = summarize(report, hashlib.sha256(profile).hexdigest(), module_hashes, args.failure_category)
    result["source_report_sha256"] = hashlib.sha256(source).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"state": result["state"], "thirty_minute_soak_verified": result["thirty_minute_soak_verified"],
                      "unverified_controls": result["unverified_controls"]}))


if __name__ == "__main__":
    main()
