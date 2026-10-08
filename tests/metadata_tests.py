"""Offline tests: descriptors, demo schema, and authentication capture exclusion."""
import json
import struct
import sys
import lzma
import zlib
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import bootstrap_relay
import extract_metadata as metadata
import extract_profile as profile


def varint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def integer(number, value):
    return varint(number << 3) + varint(value)


def string(number, value):
    if isinstance(value, str):
        value = value.encode()
    return varint((number << 3) | 2) + varint(len(value)) + value


def send_tables():
    prop = integer(1, 0) + string(2, "m_iHealth") + integer(3, 1) + integer(9, 10)
    table = string(2, "DT_Player") + integer(3, 1) + string(4, prop)
    terminator = integer(1, 1)
    return (varint(9) + varint(len(table)) + table + varint(9) + varint(len(terminator)) + terminator
            + struct.pack("<HH", 1, 0) + b"CCSPlayer\0DT_Player\0")


def demo(data=None):
    payload = send_tables() if data is None else data
    header = b"HL2DEMO\0" + struct.pack("<II", 4, 13790) + bytes(1072 - 16)
    datatables = b"\6" + bytes(5) + struct.pack("<I", len(payload)) + payload
    # Empty ordinary packet marks a real recorder's active gameplay state.
    packet = b"\2" + bytes(5) + bytes(160) + bytes(4)
    return header + datatables + packet + b"\7" + bytes(5)


class MetadataTests(unittest.TestCase):
    def test_varint_bounds(self):
        self.assertEqual(metadata.varint(varint(2 ** 64 - 1)), (2 ** 64 - 1, 10))
        for malformed in (b"\x80", b"\x80" * 11, b"\xff" * 9 + b"\x02"):
            with self.assertRaises(metadata.FormatError):
                metadata.varint(malformed)

    def test_descriptor_exact_boundary_with_nested_zero(self):
        message = string(1, "Vector") + string(2, string(1, "x") + integer(3, 1) + integer(4, 1) + integer(5, 2))
        descriptor = string(1, "example.proto") + string(4, message) + string(8, b"\x80\x01\x00")
        found = metadata.extract_descriptors(b"junk" + descriptor + b"\0unrelated")
        self.assertEqual(found["example.proto"][1], descriptor)
        self.assertEqual(found["example.proto"][2]["messages"][0]["fields"][0]["name"], "x")

    def test_descriptor_rejects_truncated_fields(self):
        with self.assertRaises(metadata.FormatError):
            metadata.fields(b"\x0a\x05a")
        self.assertEqual(metadata.extract_descriptors(b"\x0a\x05bad.proto\0"), {})

    def test_relay_excludes_every_connectionless_packet(self):
        auth = b"\xff\xff\xff\xffconnect STEAM_TICKET_SECRET"
        self.assertIsNone(bootstrap_relay.capture_record("client_to_server", auth))
        self.assertIsNone(bootstrap_relay.capture_record("server_to_client", b"\xff" * 4 + b"challenge"))
        self.assertIsNone(bootstrap_relay.capture_record("client_to_server", b"a"))
        captured = bootstrap_relay.capture_record("server_to_client", b"\xfe\xff\xff\xfffragment", 123)
        self.assertEqual(captured["timestamp_ns"], 123)
        self.assertEqual(bytes.fromhex(captured["hex"]), b"\xfe\xff\xff\xfffragment")

    def test_entity_schema_extracts_names_and_fields(self):
        schema = profile.parse_datatables(send_tables())
        self.assertEqual(schema["classes"], [{"id": 0, "name": "CCSPlayer", "table": "DT_Player"}])
        self.assertEqual(schema["send_tables"][0]["props"][0]["bits"], 10)
        self.assertTrue(schema["send_tables"][0]["needs_decoder"])

    def test_demo_merges_only_sanitized_metadata(self):
        base = {"host_version": 13881, "app_id": 730, "bootstrap": {}}
        info = {"send_table_crc": 0x12345678, "ticket_hex": "secret", "steam_id": 123}
        merged = profile.merge_profile(base, demo(), info)
        self.assertTrue(merged["bootstrap"]["stock_signon_verified"])
        self.assertEqual(merged["send_table_crc"], 0x12345678)
        self.assertNotIn("secret", json.dumps(merged))
        self.assertNotIn("steam_id", merged["bootstrap"]["client_info_evidence"])

    def test_crc_is_never_inferred(self):
        merged = profile.merge_profile({"host_version": 13881, "app_id": 730}, demo())
        self.assertNotIn("send_table_crc", merged)
        for bad in (True, -1, 2 ** 32, "123", None):
            with self.assertRaises(metadata.FormatError):
                profile.merge_profile({"host_version": 13881, "app_id": 730}, demo(), {"send_table_crc": bad})

    def test_full_signon_is_six_not_changelevel_seven(self):
        observed = {"full_signon_seen": False}
        changelevel = integer(1, 7)
        profile.packet_metadata(varint(7) + varint(len(changelevel)) + changelevel, observed)
        self.assertFalse(observed["full_signon_seen"])
        full = integer(1, 6)
        profile.packet_metadata(varint(7) + varint(len(full)) + full, observed)
        self.assertTrue(observed["full_signon_seen"])

    def test_integrity_records_are_carried_to_runtime_profile(self):
        records = [{"protobuf_hex": string(1, "GAME").hex()}]
        merged = profile.merge_profile({"host_version": 13881, "app_id": 730}, demo(),
                                       integrity={"requirements_verified": True, "requirements": [], "records": records})
        self.assertEqual(merged["integrity_records"], records)
        with self.assertRaises(metadata.FormatError):
            profile.merge_profile({"host_version": 13881, "app_id": 730}, demo(),
                                  integrity={"requirements_verified": True, "requirements": [], "records": [{"protobuf_hex": "f"}]})

    def test_dictionary_order_crc_and_encoding_width(self):
        raw = b"models/player.mdl\0materials/wall.vmt\0"
        result = profile.dictionary_metadata(raw)
        self.assertEqual(result["dictionary"], ["models/player.mdl", "materials/wall.vmt"])
        self.assertEqual(result["dictionary_bits"], 2)
        self.assertEqual(result["dictionary_crc"], zlib.crc32(raw))
        compressed = lzma.compress(raw, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 20, "lc": 3, "lp": 0, "pb": 2}])
        valve = b"LZMA" + struct.pack("<II", len(raw), len(compressed)) + bytes([93]) + struct.pack("<I", 1 << 20) + compressed
        self.assertEqual(profile.dictionary_metadata(valve), result)
        with self.assertRaises(metadata.FormatError):
            profile.dictionary_metadata(raw[:-1])

    def test_demo_truncation_and_unknown_table_rejected(self):
        with self.assertRaises(metadata.FormatError):
            profile.parse_demo(demo()[:1100])
        malformed = send_tables().replace(b"DT_Player\0", b"DT_Missin\0")
        with self.assertRaises(metadata.FormatError):
            profile.parse_datatables(malformed)


if __name__ == "__main__":
    unittest.main()
