#!/usr/bin/env python3
"""Extract embedded FileDescriptorProto data without loading game binaries.

Uses only Python's standard library. The output is portable protocol metadata;
the installed DLLs are needed only for this development-time extraction.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path


class FormatError(ValueError):
    pass


def varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise FormatError("truncated protobuf varint")
        byte = data[offset]
        offset += 1
        if shift == 63 and byte > 1:
            raise FormatError("protobuf varint exceeds uint64")
        value |= (byte & 127) << shift
        if not byte & 128:
            return value, offset
    raise FormatError("protobuf varint exceeds ten bytes")


def fields(data: bytes) -> list[tuple[int, int, int | bytes]]:
    result = []
    offset = 0
    while offset < len(data):
        tag, offset = varint(data, offset)
        number, wire = tag >> 3, tag & 7
        if not number or number > 0x1FFFFFFF:
            raise FormatError("invalid protobuf field number")
        if wire == 0:
            value, offset = varint(data, offset)
        elif wire in (1, 5):
            length = 8 if wire == 1 else 4
            if offset + length > len(data):
                raise FormatError("truncated fixed protobuf field")
            value = data[offset:offset + length]
            offset += length
        elif wire == 2:
            length, offset = varint(data, offset)
            if offset + length > len(data):
                raise FormatError("truncated protobuf bytes")
            value = data[offset:offset + length]
            offset += length
        else:
            raise FormatError(f"unsupported protobuf wire type {wire}")
        result.append((number, wire, value))
    return result


def first(data: bytes, number: int, default=None):
    for field, _, value in fields(data):
        if field == number:
            return value
    return default


def text(data: bytes, number: int, default: str = "") -> str:
    value = first(data, number, default.encode())
    if not isinstance(value, bytes):
        raise FormatError("expected protobuf string")
    return value.decode("utf-8")


def repeated(data: bytes, number: int) -> list:
    return [value for field, _, value in fields(data) if field == number]


def descriptor_length(binary: bytes, offset: int) -> int:
    """Embedded generated descriptors have a null terminator after top fields.

    Only FileDescriptorProto's actual top-level fields/wire types are accepted;
    nested zero bytes are consumed according to their length prefixes.
    """
    start = offset
    allowed = {1: 2, 2: 2, 3: 2, 4: 2, 5: 2, 6: 2, 7: 2, 8: 2, 9: 2,
               10: (0, 2), 11: (0, 2), 12: 2}
    while offset < len(binary) and offset - start <= 4 * 1024 * 1024:
        if binary[offset] == 0:
            return offset - start
        tag, following = varint(binary, offset)
        number, wire = tag >> 3, tag & 7
        expected = allowed.get(number)
        if wire != expected and not isinstance(expected, tuple):
            return offset - start
        if isinstance(expected, tuple) and wire not in expected:
            return offset - start
        if wire == 0:
            _, offset = varint(binary, following)
        else:
            length, following = varint(binary, following)
            offset = following + length
            if offset > len(binary):
                raise FormatError("descriptor extends beyond binary")
    raise FormatError("missing descriptor boundary")


def enum_summary(data: bytes) -> dict:
    values = []
    for value in repeated(data, 2):
        number = first(value, 2, 0)
        if number >= 1 << 63:
            number -= 1 << 64
        values.append({"name": text(value, 1), "number": number})
    return {"name": text(data, 1), "values": values}


def field_summary(data: bytes) -> dict:
    result = {"name": text(data, 1), "number": first(data, 3, 0),
              "label": first(data, 4, 1), "type": first(data, 5, 0)}
    for key, number in (("type_name", 6), ("default_value", 7), ("json_name", 10)):
        if first(data, number) is not None:
            result[key] = text(data, number)
    return result


def message_summary(data: bytes) -> dict:
    return {"name": text(data, 1), "fields": [field_summary(p) for p in repeated(data, 2)],
            "messages": [message_summary(p) for p in repeated(data, 3)],
            "enums": [enum_summary(p) for p in repeated(data, 4)]}


def descriptor_summary(data: bytes) -> dict:
    return {"name": text(data, 1), "package": text(data, 2),
            "dependencies": [p.decode("utf-8") for p in repeated(data, 3)],
            "messages": [message_summary(p) for p in repeated(data, 4)],
            "enums": [enum_summary(p) for p in repeated(data, 5)]}


def extract_descriptors(binary: bytes) -> dict[str, tuple[int, bytes, dict]]:
    result = {}
    for match in re.finditer(rb"[a-zA-Z0-9_./-]+\.proto", binary):
        name = match.group()
        offset = match.start() - 2
        if len(name) >= 128 or offset < 0 or binary[offset:match.start()] != bytes((10, len(name))):
            continue
        try:
            length = descriptor_length(binary, offset)
            descriptor = binary[offset:offset + length]
            summary = descriptor_summary(descriptor)
            if summary["name"] != name.decode() or not (summary["messages"] or summary["enums"]):
                continue
        except (FormatError, UnicodeDecodeError, TypeError):
            # Ordinary strings which look like descriptor prefixes are not data.
            continue
        if summary["name"] in result and result[summary["name"]][1] != descriptor:
            raise FormatError(f"conflicting embedded descriptors for {summary['name']}")
        result[summary["name"]] = (offset, descriptor, summary)
    return result


def steam_info(path: Path) -> dict[str, str]:
    result = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def extract(game: Path, output: Path) -> dict:
    info = steam_info(game / "csgo" / "steam.inf")
    if info.get("PatchVersion") != "1.38.8.1" or info.get("appID") != "730":
        raise FormatError("installed game is not CS:GO Legacy 1.38.8.1 / AppID 730")
    directory = output.parent / "descriptors"
    directory.mkdir(parents=True, exist_ok=True)
    all_descriptors = {}
    provenance = []
    for relative in (Path("bin/engine.dll"), Path("csgo/bin/client.dll")):
        binary = (game / relative).read_bytes()
        extracted = extract_descriptors(binary)
        if not extracted:
            raise FormatError(f"no protobuf descriptors found in {relative}")
        provenance.append({"file": relative.as_posix(), "sha256": hashlib.sha256(binary).hexdigest(), "bytes": len(binary)})
        for name, (offset, descriptor, summary) in extracted.items():
            digest = hashlib.sha256(descriptor).hexdigest()
            if name in all_descriptors:
                if all_descriptors[name]["sha256"] != digest:
                    raise FormatError(f"engine/client disagree on descriptor {name}")
                all_descriptors[name]["sources"].append({"file": relative.as_posix(), "offset": offset})
                continue
            # Filenames derive from validated protobuf names, never an arbitrary path.
            filename = name.replace("/", "_").replace("\\", "_") + ".bin"
            (directory / filename).write_bytes(descriptor)
            (directory / (filename + ".json")).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
            all_descriptors[name] = {"name": name, "path": "descriptors/" + filename,
                                     "sha256": digest, "bytes": len(descriptor),
                                     "sources": [{"file": relative.as_posix(), "offset": offset}], **summary}
    if "netmessages.proto" not in all_descriptors:
        raise FormatError("netmessages.proto descriptor missing")
    profile = {"format_version": 1, "host_version": 13881, "app_id": 730,
               "patch_version": info["PatchVersion"], "steam_info": info,
               "provenance": provenance, "descriptor_files": list(all_descriptors.values()),
               "send_table_crc": None, "entity_schema": {"send_tables": [], "classes": [], "dictionary": []},
               "integrity": {"requirements_verified": False, "requirements": []},
               "bootstrap": {"stock_signon_verified": False, "send_table_crc_verified": False}}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    return profile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--game", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("profiles/legacy_13881.json"))
    args = parser.parse_args()
    try:
        profile = extract(args.game, args.output)
    except (OSError, FormatError) as error:
        parser.exit(1, f"metadata extraction failed: {error}\n")
    print(f"Extracted {len(profile['descriptor_files'])} exact protobuf descriptors to {args.output}")
    print("Stock signon, send-table CRC, entity schema, and integrity requirements remain unverified.")


if __name__ == "__main__":
    main()
