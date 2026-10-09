"""Audit x86 standalone-client file-open paths with an existing private CDB debugger.

Example (run only after other live validation has finished):
  python tools/audit_runtime_files.py --output artifacts/file-audit --game-root GAME -- \
    PACKAGE/headless-csgo.exe --json --connect --run-seconds 30 --profile ABSOLUTE_PROFILE

The debuggee's working directory is the output directory. Supply absolute paths.
Only native file-open arguments, process IDs and loaded module paths are retained.
No symbols are downloaded, no kernel trace/service is installed, and no buffers or
authentication ticket contents are inspected. CDB startup/loading before its first
breakpoint is represented by module snapshots, not a complete early file-open trace.
"""
from __future__ import annotations

import argparse
import collections
import ctypes
import hashlib
import json
import ntpath
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import time


DEFAULT_CDB = Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe")
MODULE_LINE = re.compile(r"^\s*[0-9a-fA-F`]{8,}\s+[0-9a-fA-F`]{8,}\s+\S+\s+(.+?)\s*$")
NATIVE_VOLUMES: dict[str, str] = {}
if os.name == "nt":
    query_device = ctypes.WinDLL("kernel32", use_last_error=True).QueryDosDeviceW
    query_device.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    query_device.restype = ctypes.c_uint32
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        buffer = ctypes.create_unicode_buffer(32768)
        if query_device(letter + ":", buffer, len(buffer)):
            NATIVE_VOLUMES[buffer.value.casefold()] = letter + ":"


def canonical_path(path: str) -> str:
    path = path.strip().strip('"').replace("/", "\\")
    if not path:
        return ""
    for prefix in ("\\??\\", "\\\\?\\"):
        if path.startswith(prefix):
            path = path[len(prefix):]
            break
    for native, drive in NATIVE_VOLUMES.items():
        if path.casefold() == native or path.casefold().startswith(native + "\\"):
            path = drive + path[len(native):]
            break
    return ntpath.normpath(path).rstrip("\\").casefold()


def query_root_metadata(pid: int, root: int) -> tuple[str | None, str]:
    """Query a duplicated directory handle while CDB keeps the target stopped."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.DuplicateHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.DuplicateHandle.restype = ctypes.c_int
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.GetFileType.argtypes = [ctypes.c_void_p]
    kernel.GetFileType.restype = ctypes.c_uint32
    kernel.GetFinalPathNameByHandleW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
    kernel.GetFinalPathNameByHandleW.restype = ctypes.c_uint32
    target = kernel.OpenProcess(0x0040, False, pid)  # PROCESS_DUP_HANDLE only.
    if not target:
        raise ctypes.WinError(ctypes.get_last_error())
    duplicate = ctypes.c_void_p()
    try:
        if not kernel.DuplicateHandle(target, root, kernel.GetCurrentProcess(),
                                      ctypes.byref(duplicate), 0, False, 2):
            raise ctypes.WinError(ctypes.get_last_error())
        file_type = kernel.GetFileType(duplicate) & ~0x8000
        kind = {1: "disk", 2: "character_device", 3: "pipe"}.get(file_type, "unknown")
        if kind in ("pipe", "character_device"):
            return None, kind  # These handles have no filesystem asset path.
        name = ctypes.create_unicode_buffer(32768)
        length = kernel.GetFinalPathNameByHandleW(duplicate, name, len(name), 0xA)  # Opened name, NT volume.
        if 0 < length < len(name):
            return name.value, kind
        # Object-directory roots can lack a Win32 file path. Query only their
        # native object name; this never reads target file or ticket contents.
        class UnicodeString(ctypes.Structure):
            _fields_ = [("Length", ctypes.c_uint16), ("MaximumLength", ctypes.c_uint16), ("Buffer", ctypes.c_void_p)]
        native = ctypes.WinDLL("ntdll").NtQueryObject
        native.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                           ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
        native.restype = ctypes.c_int32
        buffer = ctypes.create_string_buffer(65536)
        returned = ctypes.c_uint32()
        status = native(duplicate, 1, buffer, len(buffer), ctypes.byref(returned))  # ObjectNameInformation.
        if status < 0:
            raise OSError("Object name query failed")
        unicode = UnicodeString.from_buffer(buffer)
        start, end = ctypes.addressof(buffer), ctypes.addressof(buffer) + len(buffer)
        if unicode.Length and not unicode.Length % 2 and unicode.Buffer and start <= unicode.Buffer < end \
                and unicode.Buffer + unicode.Length <= end:
            return ctypes.wstring_at(unicode.Buffer, unicode.Length // 2), kind
        raise OSError("Root handle has no readable object name")
    finally:
        if duplicate.value:
            kernel.CloseHandle(duplicate)
        kernel.CloseHandle(target)


def query_root_stdin() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    match = re.search(r"HC_ID\|([0-9a-fA-F]+)\|([0-9a-fA-F]+)", sys.stdin.read(4096))
    if not match:
        print("HC_ROOT_FAILED|invalid_input")
        return 2
    pid, root = (int(value, 16) for value in match.groups())
    try:
        name, kind = query_root_metadata(pid, root)
        print(f"HC_ROOT_KIND|{pid:x}|{root:x}|{kind}")
        if name is not None and ("\n" in name or "\r" in name or "|" in name):
            raise OSError("Unsupported object-name characters")
        if name is not None:
            print(f"HC_ROOT_NAME|{pid:x}|{root:x}|{name}")
        return 0
    except OSError:
        print(f"HC_ROOT_FAILED|{pid:x}|{root:x}")
        return 2


def inside(path: str, root: str) -> bool:
    path, root = canonical_path(path), canonical_path(root)
    return path == root or path.startswith(root + "\\")


class Observations:
    def __init__(self, game_root: str):
        self.game_root = game_root
        self.files = collections.Counter()
        self.modules: dict[int, set[str]] = collections.defaultdict(set)
        self.armed: dict[int, dict[str, str]] = {}
        self.errors: collections.Counter[str] = collections.Counter()
        self.module_pid: int | None = None
        self.processes: set[int] = set()
        self.events: collections.Counter[str] = collections.Counter()
        self.signon_states: collections.Counter[int] = collections.Counter()
        self.full_tick: int | None = None
        self.run_complete_signon: int | None = None
        self.run_complete_tick: int | None = None
        self.active_root: dict | None = None
        self.pending_root: dict | None = None

    def core_event(self, event: dict):
        kind = event.get("type")
        if kind in ("signon", "run_complete", "error", "disconnected", "connecting"):
            self.events[kind] += 1
        if kind == "signon" and isinstance(event.get("state"), int):
            state = event["state"]
            if 0 <= state <= 7:
                self.signon_states[state] += 1
                if state == 6 and isinstance(event.get("tick"), int):
                    self.full_tick = event["tick"]
        elif kind == "run_complete":
            connection = event.get("status", {}).get("connection", {})
            if isinstance(connection.get("signon"), int):
                self.run_complete_signon = connection["signon"]
            if isinstance(connection.get("tick"), int):
                self.run_complete_tick = connection["tick"]
        elif kind == "response" and event.get("ok") is False:
            self.events["failed_response"] += 1

    def consume(self, line: str):
        # CDB can prefix command results with a debugger prompt.
        line = re.sub(r"^\s*[0-9a-fA-F]+:[0-9a-fA-F]+>\s*", "", line).strip()
        # Core JSON and debugger output can share a stdout line. Consume only
        # flags/counts/ticks, dropping all other JSON fields immediately.
        json_start = line.find("{")
        if json_start >= 0:
            try:
                event, _ = json.JSONDecoder().raw_decode(line[json_start:])
                if isinstance(event, dict) and isinstance(event.get("type"), str):
                    self.core_event(event)
                    line = line[:json_start].strip()
            except (json.JSONDecodeError, AttributeError, TypeError):
                pass
        # DbgEng can insert a checksum/symbol warning after .printf has printed
        # the marker, splitting that single output record across two lines.
        file_record = re.fullmatch(r"(?:HC_FILE\|)?([0-9a-fA-F]+)\|(NtCreateFile|NtOpenFile)\|([0-9a-fA-F]+)\|(.*)", line)
        if file_record:
            pid, api, root, path = file_record.groups()
            pid, root = int(pid, 16), int(root, 16)
            root_path = ""
            root_kind = ""
            if root and self.pending_root and (
                    self.pending_root["pid"], self.pending_root["api"], self.pending_root["handle"]) == (pid, api, root):
                root_path = self.pending_root.get("name") or ""
                root_kind = self.pending_root.get("kind") or ""
            self.pending_root = None  # Snapshot applies to this call only; handles can be reused.
            resolved = canonical_path(root_path.rstrip("\\") + ("\\" + path if path else "")) if root_path else (
                canonical_path(path) if not root else "")
            self.files[(pid, api, root, path, root_path, resolved, root_kind)] += 1
            return
        root_record = re.fullmatch(r"(?:HC_ROOT\|)?([0-9a-fA-F]+)\|(NtCreateFile|NtOpenFile)\|([0-9a-fA-F]+)", line)
        if root_record:
            pid, api, root = root_record.groups()
            self.active_root = {"pid": int(pid, 16), "api": api, "handle": int(root, 16), "name": None, "kind": None}
        elif line.startswith("HC_END_ROOT"):
            self.pending_root, self.active_root = self.active_root, None
        elif self.active_root is not None:
            name = re.fullmatch(r"HC_ROOT_NAME\|([0-9a-fA-F]+)\|([0-9a-fA-F]+)\|(.*)", line)
            if name and (int(name.group(1), 16), int(name.group(2), 16)) == (
                    self.active_root["pid"], self.active_root["handle"]):
                self.active_root["name"] = name.group(3)
            kind = re.fullmatch(r"HC_ROOT_KIND\|([0-9a-fA-F]+)\|([0-9a-fA-F]+)\|(disk|pipe|character_device|unknown)", line)
            if kind and (int(kind.group(1), 16), int(kind.group(2), 16)) == (
                    self.active_root["pid"], self.active_root["handle"]):
                self.active_root["kind"] = kind.group(3)
        elif line.startswith("HC_PROCESS|"):
            self.processes.add(int(line.split("|")[1], 16))
        elif line.startswith("HC_ARMED|"):
            parts = line.split("|")
            if len(parts) == 4 and all(re.fullmatch(r"[0-9a-fA-F`]+", address) and
                                      int(address.replace("`", ""), 16) for address in parts[2:]):
                pid = int(parts[1], 16)
                self.armed[pid] = {"NtCreateFile": parts[2], "NtOpenFile": parts[3]}
        elif line.startswith("HC_MODULES|"):
            self.module_pid = int(line.split("|")[1], 16)
        elif line.startswith("HC_END_MODULES"):
            self.module_pid = None
        elif self.module_pid is not None:
            match = MODULE_LINE.match(line)
            if match:
                self.modules[self.module_pid].add(match.group(1))
        for needle in ("Memory access error", "Syntax error", "Couldn't resolve error",
                       "Unable to resolve breakpoint", "Couldn't open process"):
            if needle.casefold() in line.casefold():
                self.errors[needle] += 1

    def summary(self):
        files = [{"pid": pid, "api": api, "root_directory_handle": root,
                  "path": path, "root_directory_path": root_path or None,
                  "root_handle_type": root_kind or None,
                  "root_resolution": "Synchronous duplicate-handle name query at breakpoint" if root_path else (
                      "GetFileType positively identifies a non-filesystem empty-name root" if root and not path
                      and root_kind in ("pipe", "character_device") else None),
                  "non_filesystem_root": bool(root and not path and root_kind in ("pipe", "character_device")),
                  "resolved_path": resolved or None, "count": count,
                  "inside_game_installation": inside(resolved, self.game_root) if resolved else (
                      False if root and not path and root_kind in ("pipe", "character_device") else None)}
                 for (pid, api, root, path, root_path, resolved, root_kind), count in sorted(self.files.items())]
        modules = [{"pid": pid, "path": path, "inside_game_installation": inside(path, self.game_root)}
                   for pid, paths in sorted(self.modules.items()) for path in sorted(paths)]
        return {
            "format": 2, "method": "Private x86 CDB -o native-file-open breakpoints",
            "game_root": self.game_root, "processes": sorted(self.processes),
            "breakpoints": {str(pid): values for pid, values in sorted(self.armed.items())},
            "file_open_calls": sum(self.files.values()), "file_opens": files,
            "loaded_modules": modules,
            "game_file_open_calls": sum(item["count"] for item in files if item["inside_game_installation"]),
            "game_modules": [item for item in modules if item["inside_game_installation"]],
            "relative_root_calls": sum(item["count"] for item in files if item["root_directory_handle"]),
            "relative_root_path_resolved_calls": sum(item["count"] for item in files if item["root_directory_handle"] and item["resolved_path"]),
            "relative_root_nonfilesystem_calls": sum(item["count"] for item in files if item["non_filesystem_root"]),
            "relative_root_resolved_calls": sum(item["count"] for item in files if item["root_directory_handle"] and (item["resolved_path"] or item["non_filesystem_root"])),
            "relative_root_unresolved_calls": sum(item["count"] for item in files if item["root_directory_handle"] and not item["resolved_path"] and not item["non_filesystem_root"]),
            "nt_volume_mappings": NATIVE_VOLUMES,
            "debugger_errors": dict(self.errors),
            "core_observations": {"event_counts": dict(self.events),
                                  "signon_states": {str(state): count for state, count in sorted(self.signon_states.items())},
                                  "full_observed": bool(self.signon_states[6]), "full_tick": self.full_tick,
                                  "run_complete_signon": self.run_complete_signon, "run_complete_tick": self.run_complete_tick},
            "coverage": {
                "native_apis": ["NtCreateFile", "NtOpenFile"], "child_processes": True,
                "x86_object_attributes_name_offset": 8,
                "x86_stack_object_attributes_argument_offset": 12,
                "unicode": "CDB %msu reads the counted UNICODE_STRING, not file contents.",
                "limitations": ["File opens before CDB's initial breakpoint are not intercepted; module snapshots cover loaded images.",
                                "RootDirectory names are queried synchronously for each call while CDB keeps the target stopped; unresolved relative calls prevent verification.",
                                "Only positively identified pipe/character handles with empty relative names are classified as non-filesystem; missing disk/unknown names remain unresolved.",
                                "This observes native API arguments, not successful read lengths or direct system calls that bypass ntdll exports.",
                                "Steam client's separate process is outside the standalone-client audit."]
            }
        }


def write_scripts(directory: Path):
    modules = '.printf "HC_MODULES|%x\\n", @$tpid\nlmf\n.printf "HC_END_MODULES\\n"\n'
    install = '.printf "HC_PROCESS|%x\\n", @$tpid\n'
    for api in ("NtCreateFile", "NtOpenFile"):
        # x86 stdcall: OBJECT_ATTRIBUTES* is argument 3 at ESP+12. Its
        # RootDirectory is at +4; ObjectName (UNICODE_STRING*) is at +8.
        (directory / f"audit_call_{api}.cdb").write_text(
            '.if (poi(poi(@esp+0xc)+4) != 0) { '
            f'.printf "HC_ROOT|%x|{api}|%x\\n", @$tpid, poi(poi(@esp+0xc)+4); }}\n'
            '.if (poi(poi(@esp+0xc)+4) != 0) { $$<audit_query_root.cdb; }\n'
            '.if (poi(poi(@esp+0xc)+4) != 0) { .printf "HC_END_ROOT\\n"; }\n'
            f'.printf "HC_FILE|%x|{api}|%x|%msu\\n", '
            '@$tpid, poi(poi(@esp+0xc)+4), poi(poi(@esp+0xc)+8)\ngc\n', encoding="ascii")
        install += f'bu ntdll!{api} "$$<audit_call_{api}.cdb"\n'
    # Keep .shell on its own uncondensed script line. The root-query subprocess receives
    # only PID/handle numbers, and CDB waits for it before continuing the target.
    # A relative script name also avoids CDB .shell's quoting of a source path
    # containing spaces. This artifact is only a copy of our development tool.
    (directory / "audit_root_name.py").write_text(Path(__file__).read_text(encoding="utf-8"), encoding="utf-8")
    (directory / "audit_query_root.cdb").write_text(
        '.shell -ci ".printf \\"HC_ID|%x|%x\\\\n\\", @$tpid, poi(poi(@esp+0xc)+4)" '
        f'"{sys.executable}" audit_root_name.py --query-root-stdin\n', encoding="utf-8")
    install += '.printf "HC_ARMED|%x|%p|%p\\n", @$tpid, ntdll!NtCreateFile, ntdll!NtOpenFile\n'
    install += modules + 'g\n'
    (directory / "audit_install.cdb").write_text(install, encoding="ascii")
    (directory / "audit_modules.cdb").write_text(modules + "g\n", encoding="ascii")
    (directory / "audit_start.cdb").write_text(
        'sxe -c "g" cpr\n'
        'sxe -c "$><audit_install.cdb" ibp\n'
        'sxe -c "$><audit_modules.cdb" ld\n'
        'sxd epr\n$><audit_install.cdb\n', encoding="ascii")


def main():
    if sys.argv[1:] == ["--query-root-stdin"]:
        return query_root_stdin()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cdb", type=Path, default=DEFAULT_CDB)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--game-root", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=90)
    parser.add_argument("--expect-path", type=Path, help="Offline fixture must observe this exact file in both parent and child.")
    parser.add_argument("--require-full", action="store_true", help="Require a live FULL/run_complete result and the audited client plus root-query subprocess.")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("This tool requires Windows and the installed x86 CDB debugger.")
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("Provide an absolute x86 executable and arguments after --.")
    command[0] = str(Path(command[0]).resolve(strict=True))
    if not args.cdb.is_file() or "x86" not in str(args.cdb).casefold():
        parser.error("Provide an installed x86 CDB executable.")
    if args.timeout <= 0:
        parser.error("Timeout must be positive.")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    write_scripts(output)
    observer = Observations(str(args.game_root.resolve()))
    environment = dict(os.environ)
    environment.pop("_NT_SYMBOL_PATH", None)
    environment.pop("_NT_ALT_SYMBOL_PATH", None)
    process = subprocess.Popen([str(args.cdb), "-sins", "-y", ".", "-nosqm", "-hd", "-o", "-G",
                                "-cf", "audit_start.cdb", *command],
                               cwd=output, env=environment, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, encoding="utf-8", errors="replace",
                               creationflags=subprocess.CREATE_NO_WINDOW)
    lines: queue.Queue[str | None] = queue.Queue()
    def reader():
        try:
            for line in process.stdout:
                lines.put(line.rstrip("\r\n"))
        finally:
            lines.put(None)
    worker = threading.Thread(target=reader, daemon=True)
    worker.start()
    start = time.monotonic()
    timed_out = False
    while True:
        remaining = args.timeout - (time.monotonic() - start)
        if remaining <= 0:
            timed_out = True
            process.kill()
            break
        try:
            line = lines.get(timeout=min(remaining, 1))
        except queue.Empty:
            continue
        if line is None:
            break
        observer.consume(line)
    process.wait(timeout=10)
    worker.join(timeout=2)
    while not lines.empty():
        line = lines.get_nowait()
        if line is not None:
            observer.consume(line)
    result = observer.summary()
    result.update({"elapsed_seconds": round(time.monotonic() - start, 3), "debugger_exit_code": process.returncode,
                   "timed_out": timed_out, "executable": command[0], "cdb": str(args.cdb),
                   "executable_sha256": hashlib.sha256(Path(command[0]).read_bytes()).hexdigest()})
    if args.expect_path:
        expected = canonical_path(str(args.expect_path.resolve()))
        pids = sorted({pid for (pid, _, _, _, _, resolved, _) in observer.files if resolved == expected})
        apis = sorted({api for (_, api, _, _, _, resolved, _) in observer.files if resolved == expected})
        counted_unicode = not any("SENTINEL_OUTSIDE_UNICODE_STRING_LENGTH" in path for (_, _, _, path, _, _, _) in observer.files)
        relative = {pid for (pid, _, root, _, root_path, resolved, _) in observer.files if root and root_path and resolved == expected}
        pipe_pids = {pid for (pid, _, root, path, _, _, kind) in observer.files if root and not path and kind == "pipe"}
        result["fixture"] = {"expected_path": str(args.expect_path.resolve()), "observed_pids": pids,
                             "observed_apis": apis, "counted_unicode_correct": counted_unicode,
                             "relative_path_observed_pids": sorted(relative),
                             "nonfilesystem_pipe_observed_pids": sorted(pipe_pids),
                             "passed": len(pids) >= 2 and apis == ["NtCreateFile", "NtOpenFile"] and counted_unicode
                                       and relative == set(pids) and pipe_pids == set(pids) and all(pid in observer.armed for pid in pids)}
    base_verified = (not timed_out and process.returncode == 0 and not result["debugger_errors"]
                     and result["file_open_calls"] > 0 and observer.processes == set(observer.armed)
                     and result["relative_root_unresolved_calls"] == 0)
    core = result["core_observations"]
    live_verified = (len(observer.armed) >= 2 and core["full_observed"]
                     and core["run_complete_signon"] == 6 and core["event_counts"].get("run_complete", 0) == 1
                     and not observer.events["error"] and not observer.events["failed_response"]
                     and observer.events["disconnected"] == 1 and result["game_file_open_calls"] == 0
                     and not result["game_modules"])
    result["required_full"] = args.require_full
    result["audit_verified"] = bool(base_verified and (live_verified if args.require_full else True)
                                    and result.get("fixture", {}).get("passed", True))
    report = output / "file-audit.json"
    report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(report), "file_open_calls": result["file_open_calls"],
                      "game_file_open_calls": result["game_file_open_calls"], "processes": result["processes"],
                      "timed_out": timed_out, "audit_verified": result["audit_verified"], "fixture": result.get("fixture")}))
    return 0 if result["audit_verified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
