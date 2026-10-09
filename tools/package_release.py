"""Package explicitly allowed client files; no captures, credentials, or engine assets."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FIXED_TIME = (2026, 1, 1, 0, 0, 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration", choices=("Debug", "Release"), default="Release")
    parser.add_argument("--build", type=Path, default=ROOT / "build")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/release")
    args = parser.parse_args()
    files = {}
    for name in ("headless-csgo.exe",):
        files[name] = args.build / args.configuration / name
    for name in ("README.md", "VALIDATION.md", "THIRD_PARTY_NOTICES.md", "dependencies.lock.json",
                 "third_party/nlohmann/LICENSE.MIT", "third_party/qrcodegen/LICENSE.MIT",
                 "examples/control.py", "profiles/legacy_13881.json"):
        files[name] = ROOT / name
    for path in sorted((ROOT / "profiles/descriptors").glob("*")):
        if path.is_file():
            files[path.relative_to(ROOT).as_posix()] = path
    for name in ("offline_replay.json", "runtime_file_audit_fixture.json"):
        path = ROOT / "validation" / name
        if path.is_file():
            files[path.relative_to(ROOT).as_posix()] = path
    for name, path in files.items():
        if not path.is_file():
            raise FileNotFoundError(f"Required package input is missing: {name}")
    lock = json.loads(files["dependencies.lock.json"].read_text(encoding="utf-8"))
    for component in ("nlohmann", "qrcodegen"):
        for entry in lock["components"][component]["files"]:
            path = ROOT / entry["path"]
            if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
                raise ValueError(f"Pinned dependency differs from the lock: {path}")
    payload = {name: path.read_bytes() for name, path in sorted(files.items())}
    manifest = {
        "format": 1, "host_version": 13881, "architecture": "x86", "configuration": args.configuration,
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "files": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in payload.items()},
    }
    payload["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    args.output.mkdir(parents=True, exist_ok=True)
    output = args.output / f"headless-csgo-13881-win32-{args.configuration.lower()}.zip"
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(payload.items()):
            info = zipfile.ZipInfo(name, FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(".zip.sha256").write_text(digest + "  " + output.name + "\n", encoding="ascii")
    print(json.dumps({"package": str(output.resolve()), "sha256": digest, "files": len(payload)}))


if __name__ == "__main__":
    main()
