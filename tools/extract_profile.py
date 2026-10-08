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


def integrity_record(record: dict) -> dict:
    payload = record.get("protobuf_hex") if isinstance(record, dict) else None
    if not isinstance(payload, str) or len(payload) % 2 or len(payload) > 65536:
        raise FormatError("invalid integrity record encoding")
    try:
        raw = bytes.fromhex(payload)
        parsed = fields(raw)
    except ValueError as error:
        raise FormatError("invalid integrity protobuf record") from error
    expected_types = {1: 0, 2: 2, 3: 0, 4: 2, 5: 0, 6: 2, 7: 0, 8: 0, 9: 0, 10: 0, 11: 0}
    if any(number not in expected_types or expected_types[number] != wire for number, wire, _ in parsed):
        raise FormatError("integrity record does not match exact CCLCMsg_FileCRCCheck schema")
    if len({number for number, _, _ in parsed}) != len(parsed):
        raise FormatError("duplicate integrity protobuf fields")
    path_code = signed32(first(raw, 1, 0))
    path = ("GAME", "MOD")[path_code] if path_code in (0, 1) else text(raw, 2)
    if path_code not in (-1, 0, 1) or not path:
        raise FormatError("unknown integrity path identifier")
    filename_code = signed32(first(raw, 3, 0))
    if filename_code not in (-1, 0, 1, 2, 3):
        raise FormatError("unknown integrity filename prefix")
    filename = text(raw, 4)
    if filename_code >= 0:
        filename = ("materials", "models", "sounds", "scripts")[filename_code] + "/" + filename
    filename = filename.replace("\\", "/")
    if not filename or filename.startswith("/") or ":" in filename or any(part in ("", ".", "..") for part in filename.split("/")):
        raise FormatError("invalid relative integrity filename")
    md5 = first(raw, 6, b"")
    if not isinstance(md5, bytes) or len(md5) != 16:
        raise FormatError("integrity record requires a 16-byte MD5")
    result = {"protobuf_hex": raw.hex(), "protobuf_sha256": hashlib.sha256(raw).hexdigest(),
              "path": path, "filename": filename, "md5_hex": md5.hex(), "crc": first(raw, 7, 0)}
    for name, number in (("file_fraction", 5), ("file_hash_type", 8), ("file_len", 9), ("pack_file_id", 10), ("pack_file_number", 11)):
        result[name] = signed32(first(raw, number, 0))
    if result["file_hash_type"] not in (0, 1, 2) or result["file_len"] < 0 or result["file_fraction"] < 0:
        raise FormatError("invalid integrity file hash parameters")
    return result


def verify_integrity_sources(records: list[dict], game: Path) -> None:
    """Verify reported full-file/VPK chunk hashes; never load these at runtime."""
    game = game.resolve()
    for record in records:
        if record["path"] not in ("GAME", "MOD") or record["file_hash_type"] != 1:
            raise FormatError(f"unsupported integrity source verification: {record['path']}/{record['filename']}")
        candidates = [game / "csgo" / record["filename"]]
        if record["path"] == "GAME":
            candidates.append(game / "platform" / record["filename"])
        source = next((candidate.resolve() for candidate in candidates if candidate.is_file()), None)
        if source is None or not source.is_relative_to(game):
            raise FormatError(f"integrity source file missing: {record['path']}/{record['filename']}")
        offset = record["file_fraction"] if record["pack_file_id"] else 0
        length = record["file_len"]
        if not record["pack_file_id"] and source.stat().st_size != length:
            raise FormatError(f"integrity full-file length mismatch: {record['filename']}")
        if offset + length > source.stat().st_size:
            raise FormatError(f"integrity chunk exceeds source: {record['filename']}")
        remaining = length
        md5, sha256 = hashlib.md5(), hashlib.sha256()
        with source.open("rb") as data:
            data.seek(offset)
            while remaining:
                chunk = data.read(min(remaining, 1024 * 1024))
                if not chunk:
                    raise FormatError("integrity source file truncated while hashing")
                md5.update(chunk)
                sha256.update(chunk)
                remaining -= len(chunk)
        if md5.hexdigest() != record["md5_hex"]:
            raise FormatError(f"captured integrity MD5 differs from installed file: {record['filename']}@{offset}")
        record["source_verified"] = True
        record["source"] = {"file": source.relative_to(game).as_posix(), "offset": offset,
                            "bytes": length, "sha256": sha256.hexdigest()}


def whitelist_hash(value) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) != 64 or any(character not in "0123456789abcdefABCDEF" for character in value):
        raise FormatError("PureServerWhitelist SHA256 must contain 64 hexadecimal digits")
    try:
        bytes.fromhex(value)
    except ValueError as error:
        raise FormatError("invalid PureServerWhitelist SHA256") from error
    return value.lower()


def reconcile_integrity(profile: dict, evidence: dict | None = None,
                        observation: dict | None = None, game: Path | None = None) -> None:
    evidence = evidence or {}
    observation = observation or {}
    old = profile.get("integrity", {})
    observed_hash = whitelist_hash(evidence.get("pure_whitelist_sha256"))
    explicit_hash = whitelist_hash(observation.get("pure_whitelist_sha256", observation.get("whitelist_sha256")))
    previous_hash = whitelist_hash(old.get("whitelist_sha256", old.get("pure_whitelist_sha256")))
    if observed_hash and explicit_hash and observed_hash != explicit_hash:
        raise FormatError("conflicting captured PureServerWhitelist evidence")
    expected_hash = observed_hash or explicit_hash or previous_hash
    if previous_hash and expected_hash != previous_hash:
        raise FormatError("PureServerWhitelist changed; regenerate a separate matching profile")
    demo_info = profile.get("bootstrap", {}).get("demo_metadata", {}).get("server_info", {})
    map_name = evidence.get("map", demo_info.get("map_name"))
    map_crc = evidence.get("map_crc", demo_info.get("map_crc"))
    if demo_info.get("map_name") and evidence.get("map") and evidence["map"] != demo_info["map_name"]:
        raise FormatError("integrity evidence map differs from entity-schema demo")
    if demo_info.get("map_crc") is not None and evidence.get("map_crc") is not None and evidence["map_crc"] != demo_info["map_crc"]:
        raise FormatError("integrity evidence map CRC differs from entity-schema demo")
    raw_records = observation.get("records", observation.get("integrity_records", evidence.get("integrity_records", profile.get("integrity_records", []))))
    if not isinstance(raw_records, list):
        raise FormatError("invalid captured integrity records")
    records, hashes, identities = [], set(), {}
    for raw in raw_records:
        decoded = integrity_record(raw)
        identity = tuple(decoded[key] for key in ("path", "filename", "file_fraction", "file_hash_type", "file_len", "pack_file_id", "pack_file_number"))
        known = identities.get(identity)
        if known is not None and (known["md5_hex"], known["crc"]) != (decoded["md5_hex"], decoded["crc"]):
            raise FormatError(f"conflicting captured integrity hashes: {decoded['filename']}@{decoded['file_fraction']}")
        identities[identity] = decoded
        if decoded["protobuf_sha256"] not in hashes:
            records.append(decoded)
            hashes.add(decoded["protobuf_sha256"])
    if game is not None:
        verify_integrity_sources(records, game)
    mode = evidence.get("pure_mode", observation.get("pure_mode", old.get("pure_mode")))
    if mode is not None and mode not in (0, 1, 2):
        raise FormatError("invalid observed sv_pure mode")
    missing = []
    if not expected_hash:
        missing.append("PureServerWhitelist was not decoded from server_query_info entry userdata")
    if not profile.get("bootstrap", {}).get("stock_signon_verified"):
        missing.append("successful stock client FULL signon was not observed")
    if not map_name or map_crc is None:
        missing.append("captured map name and server map CRC are unavailable")
    if not records:
        missing.append("no genuine captured CCLCMsg_FileCRCCheck records are available")
    if records and not all(record.get("source_verified") for record in records):
        missing.append("captured file hashes have not been independently verified against installed files")
    requirements = [{"kind": "PureServerWhitelist", "table": "server_query_info", "entry": "PureServerWhitelist",
                     "sha256": expected_hash}] if expected_hash else []
    profile["integrity_records"] = records
    profile["integrity"] = {"requirements_verified": not missing, "requirements": requirements,
                            "whitelist_sha256": expected_hash, "pure_mode": mode,
                            "missing_requirements": missing,
                            "coverage": {"server": evidence.get("server", "151.243.93.16:27015"),
                                         "host_version": profile["host_version"], "map": map_name, "map_crc": map_crc,
                                         "record_count": len(records),
                                         "file_count": len({(record["path"], record["filename"]) for record in records}),
                                         "records_sha256": hashlib.sha256(b"".join(bytes.fromhex(record["protobuf_hex"]) for record in records)).hexdigest(),
                                         "scope": "captured files for the recorded map and exact whitelist"}}
    if evidence.get("capture_sha256"):
        profile["integrity"]["coverage"]["capture_sha256"] = evidence["capture_sha256"]


def merge_profile(profile: dict, demo_data: bytes, client_info: dict | None = None,
                  stock_signon_verified: bool = False, integrity: dict | None = None,
                  game: Path | None = None) -> dict:
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
    reconcile_integrity(profile, client_info, integrity, game)
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
        # Source deliberately transmits CRC_MapFile's internal accumulator:
        # its caller initializes it but neither caller nor CRC_MapFile finalizes.
        result = {"name": path.stem, "map_crc": crc ^ 0xFFFFFFFF, "dictionary": [], "dictionary_bits": 0,
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
    parser.add_argument("--game", type=Path, help="development-only installed files for independently verifying captured integrity hashes")
    parser.add_argument("--stock-signon-verified", action="store_true", help="record explicit successful stock signon observation")
    args = parser.parse_args()
    try:
        profile = json.loads(args.profile.read_text(encoding="utf-8-sig"))
        client_info = json.loads(args.client_info.read_text(encoding="utf-8-sig")) if args.client_info else None
        integrity = json.loads(args.integrity.read_text(encoding="utf-8-sig")) if args.integrity else None
        merged = merge_profile(profile, args.demo.read_bytes(), client_info, args.stock_signon_verified, integrity, args.game)
        if args.client_info:
            merged["bootstrap"]["client_info_evidence_sha256"] = hashlib.sha256(args.client_info.read_bytes()).hexdigest()
        if args.bsp:
            derived_map = bsp_metadata(args.bsp)
            demo_map = merged["bootstrap"]["demo_metadata"].get("server_info", {}).get("map_name", "")
            if demo_map and Path(demo_map).name != derived_map["name"]:
                raise FormatError("BSP map does not match recorded server map")
            observed_crc = merged["integrity"]["coverage"].get("map_crc")
            if observed_crc is not None and derived_map["map_crc"] != observed_crc:
                raise FormatError("installed BSP checksum does not match recorded server map")
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
