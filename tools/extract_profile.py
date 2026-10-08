#!/usr/bin/env python3
"""Merge sanitized schema and observed clientinfo evidence into a profile.

Raw demos and captures remain local: only table definitions, CRCs, map metadata
and hashes are retained. A CRC must come from decrypted clc_ClientInfo field 1;
it is never guessed from demo bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import lzma
import struct
import zipfile
import zlib
from pathlib import Path

from extract_metadata import FormatError, fields, first, repeated, text, varint

DEMO_HEADER_BYTES = 1072
DEMO_COMMAND_INFO_BYTES = 152  # two Split_t entries, 76 bytes each


class Cursor:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, count: int) -> bytes:
        if count < 0 or self.offset + count > len(self.data):
            raise FormatError("truncated demo")
        result = self.data[self.offset:self.offset + count]
        self.offset += count
        return result

    def integer(self, count: int, signed: bool = False) -> int:
        return int.from_bytes(self.take(count), "little", signed=signed)

    def blob(self) -> bytes:
        length = self.integer(4, signed=True)
        if not 0 <= length <= 64 * 1024 * 1024:
            raise FormatError("invalid demo block length")
        return self.take(length)

    def cstring(self) -> str:
        end = self.data.find(b"\0", self.offset, min(len(self.data), self.offset + 4096))
        if end < 0:
            raise FormatError("missing demo string terminator")
        result = self.data[self.offset:end].decode("utf-8")
        self.offset = end + 1
        return result

    def variable(self) -> int:
        value, self.offset = varint(self.data, self.offset)
        return value


def signed32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def float_field(data: bytes, number: int) -> float:
    value = first(data, number, b"\0" * 4)
    if not isinstance(value, bytes) or len(value) != 4:
        raise FormatError("malformed sendprop float")
    return struct.unpack("<f", value)[0]


def parse_send_table(data: bytes) -> dict | None:
    if first(data, 1, 0):
        return None
    name = text(data, 2)
    if not name:
        raise FormatError("send table has no name")
    props = []
    for prop in repeated(data, 4):
        field_type = signed32(first(prop, 1, 0))
        if not 0 <= field_type <= 7:
            raise FormatError("unsupported sendprop type")
        props.append({"type": field_type, "name": text(prop, 2),
                      "flags": signed32(first(prop, 3, 0)), "priority": signed32(first(prop, 4, 0)),
                      "table": text(prop, 5), "elements": signed32(first(prop, 6, 0)),
                      "low": float_field(prop, 7), "high": float_field(prop, 8),
                      "bits": signed32(first(prop, 9, 0))})
    return {"name": name, "needs_decoder": bool(first(data, 3, 0)), "props": props}


def parse_datatables(data: bytes) -> dict:
    cursor = Cursor(data)
    tables = []
    while True:
        message_type = cursor.variable()
        if message_type != 9:
            raise FormatError(f"expected svc_SendTable (9), received {message_type}")
        table = parse_send_table(cursor.take(cursor.variable()))
        if table is None:
            break
        tables.append(table)
        if len(tables) > 8192:
            raise FormatError("too many send tables")
    count = cursor.integer(2)
    if count > 4096:
        raise FormatError("too many server classes")
    classes = [{"id": cursor.integer(2), "name": cursor.cstring(), "table": cursor.cstring()} for _ in range(count)]
    known_tables = {table["name"] for table in tables}
    if len(known_tables) != len(tables) or len({entry["id"] for entry in classes}) != count:
        raise FormatError("duplicate send table/class identifiers")
    if any(entry["table"] not in known_tables for entry in classes):
        raise FormatError("server class references a missing send table")
    if any(cursor.data[cursor.offset:]):
        raise FormatError("unexpected trailing demo datatable content")
    return {"send_tables": tables, "classes": classes, "dictionary": []}


def packet_metadata(packet: bytes, metadata: dict) -> None:
    cursor = Cursor(packet)
    while cursor.offset < len(packet):
        command = cursor.variable()
        if command == 0 and not any(packet[cursor.offset:]):
            break
        size = cursor.variable()
        data = cursor.take(size)
        if command == 7 and first(data, 1, 0) == 6:
            metadata["full_signon_seen"] = True
        elif command == 8:
            crc = first(data, 8)
            metadata["server_info"] = {
                "protocol": first(data, 1, 0), "server_count": first(data, 2, 0),
                "map_name": text(data, 16), "tick_interval": float_field(data, 14),
                "map_crc": int.from_bytes(crc, "little") if isinstance(crc, bytes) else crc,
                "string_table_crc": int.from_bytes(first(data, 10, b"\0" * 4), "little")}


def parse_demo(data: bytes) -> tuple[dict, dict]:
    cursor = Cursor(data)
    if cursor.take(8) != b"HL2DEMO\0":
        raise FormatError("not a Source 1 demo")
    demo_protocol = cursor.integer(4)
    network_protocol = cursor.integer(4)
    if demo_protocol != 4:
        raise FormatError(f"unsupported demo protocol {demo_protocol}")
    cursor.take(DEMO_HEADER_BYTES - 16)
    schema = None
    metadata = {"demo_protocol": demo_protocol, "network_protocol": network_protocol,
                "full_signon_seen": False, "playback_packets": 0}
    while cursor.offset < len(data):
        command = cursor.integer(1)
        cursor.take(5)  # signed tick + player slot
        if command in (1, 2):
            cursor.take(DEMO_COMMAND_INFO_BYTES + 8)  # cmdinfo + incoming/outgoing sequence
            packet = cursor.blob()
            packet_metadata(packet, metadata)
            if command == 2:
                metadata["playback_packets"] += 1
        elif command == 3:
            pass
        elif command in (4, 9):
            cursor.blob()  # console command/string-table snapshot, deliberately not retained
        elif command in (5, 8):
            cursor.take(4)  # outgoing command number/custom callback index
            cursor.blob()
        elif command == 6:
            extracted = parse_datatables(cursor.blob())
            if schema is not None and schema != extracted:
                raise FormatError("demo contains differing entity schemas")
            schema = extracted
        elif command == 7:
            break
        else:
            raise FormatError(f"unknown demo command {command}")
    if schema is None or not schema["send_tables"] or not schema["classes"]:
        raise FormatError("demo does not contain usable dem_datatables")
    return schema, metadata


def merge_profile(profile: dict, demo_data: bytes, client_info: dict | None = None,
                  stock_signon_verified: bool = False, integrity: dict | None = None) -> dict:
    if profile.get("host_version") != 13881 or profile.get("app_id") != 730:
        raise FormatError("incompatible metadata profile")
    schema, metadata = parse_demo(demo_data)
    profile["entity_schema"] = schema
    bootstrap = profile.setdefault("bootstrap", {})
    bootstrap["demo_sha256"] = hashlib.sha256(demo_data).hexdigest()
    bootstrap["demo_metadata"] = metadata
    # A recorded gameplay packet proves the recorder reached active gameplay;
    # the explicit flag covers a documented observer confirmation separately.
    bootstrap["stock_signon_verified"] = bool(stock_signon_verified or metadata["full_signon_seen"] or metadata["playback_packets"])
    if client_info is not None:
        if client_info.get("host_version", 13881) != 13881 or client_info.get("server", "151.243.93.16:27015") != "151.243.93.16:27015":
            raise FormatError("clientinfo evidence belongs to a different version/server")
        crc = client_info.get("send_table_crc")
        if isinstance(crc, bool) or not isinstance(crc, int) or not 0 <= crc <= 0xFFFFFFFF:
            raise FormatError("clientinfo evidence has no valid send_table_crc")
        profile["send_table_crc"] = crc
        bootstrap["send_table_crc_verified"] = True
        if client_info.get("client_full_signon") is True:
            bootstrap["stock_signon_verified"] = True
        bootstrap["client_info_evidence"] = {key: client_info[key] for key in
                                             ("host_version", "server", "server_count", "send_table_crc", "capture_sha256") if key in client_info}
    if integrity is not None:
        if not isinstance(integrity.get("requirements_verified"), bool) or not isinstance(integrity.get("requirements"), list):
            raise FormatError("invalid integrity observations")
        records = integrity.get("records", integrity.get("integrity_records", []))
        if not isinstance(records, list):
            raise FormatError("invalid integrity records")
        for record in records:
            payload = record.get("protobuf_hex") if isinstance(record, dict) else None
            if not isinstance(payload, str) or len(payload) % 2 or len(payload) > 65536:
                raise FormatError("invalid integrity record encoding")
            try:
                raw = bytes.fromhex(payload)
                fields(raw)
            except ValueError as error:
                raise FormatError("invalid integrity protobuf record") from error
        profile["integrity_records"] = records
        profile["integrity"] = integrity
    elif client_info is not None and "integrity_records" in client_info:
        records = client_info["integrity_records"]
        if not isinstance(records, list):
            raise FormatError("invalid captured integrity records")
        profile["integrity_records"] = records
    return profile


def valve_lzma(data: bytes) -> bytes:
    if not data.startswith(b"LZMA"):
        return data
    if len(data) < 17:
        raise FormatError("truncated Valve LZMA header")
    expected, compressed = struct.unpack_from("<II", data, 4)
    properties, dictionary_size = data[12], int.from_bytes(data[13:17], "little")
    if expected > 64 * 1024 * 1024 or compressed > len(data) - 17 or properties >= 9 * 5 * 5 or dictionary_size > 256 * 1024 * 1024:
        raise FormatError("invalid Valve LZMA parameters")
    lc = properties % 9
    remainder = properties // 9
    lp, pb = remainder % 5, remainder // 5
    try:
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[
            {"id": lzma.FILTER_LZMA1, "dict_size": max(dictionary_size, 4096), "lc": lc, "lp": lp, "pb": pb}])
        result = decoder.decompress(data[17:17 + compressed], max_length=expected + 1)
    except (lzma.LZMAError, ValueError) as error:
        raise FormatError("invalid Valve LZMA dictionary") from error
    if len(result) != expected:
        raise FormatError("Valve LZMA dictionary length mismatch")
    return result


def dictionary_metadata(data: bytes) -> dict:
    raw = valve_lzma(data)
    if raw and not raw.endswith(b"\0"):
        raise FormatError("string-table dictionary is not null terminated")
    strings = [entry[:259].decode("utf-8") for entry in raw.split(b"\0") if entry]
    return {"dictionary": strings, "dictionary_bits": len(strings).bit_length(),
            "dictionary_crc": zlib.crc32(raw), "dictionary_sha256": hashlib.sha256(raw).hexdigest()}


def bsp_metadata(path: Path) -> dict:
    """Reproduce Source CRC_MapFile's physical lump ordering, excluding entities."""
    size = path.stat().st_size
    with path.open("rb") as source:
        header = source.read(1036)
        if len(header) != 1036 or header[:4] != b"VBSP" or not 19 <= int.from_bytes(header[4:8], "little") <= 21:
            raise FormatError("unsupported or truncated Source BSP")
        lumps = [struct.unpack_from("<iii4s", header, 8 + index * 16) for index in range(64)]
        for offset, length, _, _ in lumps:
            if offset < 0 or length < 0 or offset + length > size:
                raise FormatError("BSP lump extends beyond file")
        crc = 0
        for index in sorted(range(64), key=lambda number: lumps[number][0]):
            if index == 0:
                continue
            offset, length, _, _ = lumps[index]
            source.seek(offset)
            remaining = length
            while remaining:
                chunk = source.read(min(remaining, 1024 * 1024))
                if not chunk:
                    raise FormatError("truncated BSP lump")
                crc = zlib.crc32(chunk, crc)
                remaining -= len(chunk)
        result = {"name": path.stem, "map_crc": crc, "dictionary": [], "dictionary_bits": 0,
                  "dictionary_source": None}
        pak_offset, pak_length, _, _ = lumps[40]
        if pak_length:
            if pak_length > 512 * 1024 * 1024:
                raise FormatError("BSP pak lump exceeds extraction bound")
            source.seek(pak_offset)
            try:
                with zipfile.ZipFile(io.BytesIO(source.read(pak_length))) as pak:
                    for filename in ("stringtable_dictionary.dct", "stringtable_dictionary_fallback.dct"):
                        try:
                            entry = pak.getinfo(filename)
                        except KeyError:
                            continue
                        if entry.file_size > 64 * 1024 * 1024:
                            raise FormatError("BSP dictionary exceeds extraction bound")
                        result.update(dictionary_metadata(pak.read(entry)))
                        result["dictionary_source"] = filename
                        break
            except zipfile.BadZipFile as error:
                raise FormatError("invalid BSP pak ZIP") from error
        source.seek(0)
        digest = hashlib.file_digest(source, "sha256").hexdigest()
        result["bsp_sha256"] = digest
        result["bsp_bytes"] = size
        return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=Path("profiles/legacy_13881.json"))
    parser.add_argument("--demo", type=Path, required=True)
    parser.add_argument("--client-info", type=Path, help="sanitized clc_ClientInfo export containing send_table_crc")
    parser.add_argument("--integrity", type=Path, help="sanitized observed integrity requirements JSON")
    parser.add_argument("--bsp", type=Path, help="development-only matching BSP; retain only CRC and dictionary strings")
    parser.add_argument("--stock-signon-verified", action="store_true", help="record explicit successful stock signon observation")
    args = parser.parse_args()
    try:
        profile = json.loads(args.profile.read_text(encoding="utf-8-sig"))
        client_info = json.loads(args.client_info.read_text(encoding="utf-8-sig")) if args.client_info else None
        integrity = json.loads(args.integrity.read_text(encoding="utf-8-sig")) if args.integrity else None
        merged = merge_profile(profile, args.demo.read_bytes(), client_info, args.stock_signon_verified, integrity)
        if args.bsp:
            derived_map = bsp_metadata(args.bsp)
            demo_map = merged["bootstrap"]["demo_metadata"].get("server_info", {}).get("map_name", "")
            if demo_map and Path(demo_map).name != derived_map["name"]:
                raise FormatError("BSP map does not match recorded server map")
            merged["entity_schema"]["dictionary"] = derived_map["dictionary"]
            merged["entity_schema"]["dictionary_bits"] = derived_map["dictionary_bits"]
            merged["map_metadata"] = {key: value for key, value in derived_map.items() if key != "dictionary"}
        args.profile.write_text(json.dumps(merged, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"profile extraction failed: {error}\n")
    schema = merged["entity_schema"]
    print(f"Extracted {len(schema['send_tables'])} send tables and {len(schema['classes'])} server classes")
    print(f"Stock signon verified: {merged['bootstrap']['stock_signon_verified']}; CRC verified: {merged['bootstrap'].get('send_table_crc_verified', False)}")


if __name__ == "__main__":
    main()
