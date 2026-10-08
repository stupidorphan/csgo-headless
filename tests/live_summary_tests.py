"""Offline checks that delivery summaries preserve evidence and exclude secrets."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("live_summary", ROOT / "tools/summarize_live_validation.py")
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)


class SummaryTests(unittest.TestCase):
    def report(self):
        secret = "PRIVATE_AUTH_AND_IDENTITY_SENTINEL"
        local = {"entity_index": 1, "user_id": secret, "steam_id": secret, "name": secret,
                 "team": 2, "health": 100, "money": 900, "armor": 100,
                 "position": [1, 2, 3], "eye_angles": [12, 37], "duck_amount": 0.9,
                 "fields": {"anything": secret},
                 "inventory": [{"entity_index": 20, "class": "CWeaponGlock", "handle": 4116,
                                "clip": 19, "owner_steam_id": secret, "fields": {"secret": secret}}]}
        state = {"tick": 64, "map": "cs_italy", "local": local,
                 "connection": {"signon": 6, "state": "full", "received_packets": 42,
                                "last_error": secret, "ticket_hex": secret}, "round": {"secret": secret}}
        return {"server": summary.SERVER, "executable_sha256": "a" * 64, "state": "verified",
                "executable": "C:\\Users\\" + secret + "\\headless-csgo.exe", "profile": secret,
                "started_at": "2026-10-08T04:00:00+00:00", "finished_at": "2026-10-08T04:30:01+00:00",
                "controls": {"fire": {"state": "verified", "accepted_response": {"secret": secret},
                              "before": state, "after": state, "server_event": {"type": "game_event", "name": "weapon_fire",
                              "tick": 65, "values": {"userid": secret, "weapon": "glock", "silenced": False, "hex": secret}}},
                             "say": {"state": "verified", "server_echo": {"text": secret, "hex": secret}},
                             "unknown_" + secret: {"state": "verified"}},
                "soak": {"elapsed_seconds": 1800.01, "continuous_full": True, "initial": state, "final": state,
                         "measurements": [{"elapsed_seconds": 30, **state}], "activity_interval_seconds": 30,
                         "activity": [{"elapsed_seconds": 30, "input": {"forward": 0.35, "yaw": 90,
                                      "buttons": ["jump", secret], "ticket": secret}, "accepted_response": secret}]}, "full_signon": state,
                "runtime_full": {"verified": True, "processes": [{"name": "headless-csgo", "id": 123,
                                 "modules": ["C:\\Users\\" + secret + "\\steam_api.dll"]}], "stock": [],
                                 "forbidden_modules": [], "reason": secret}, "error": secret, "cleanup_error": secret}

    def test_evidence_and_privacy(self):
        report = self.report()
        path = report["runtime_full"]["processes"][0]["modules"][0]
        result = summary.summarize(report, "b" * 64, {path: "c" * 64})
        encoded = json.dumps(result)
        self.assertNotIn("PRIVATE_AUTH_AND_IDENTITY_SENTINEL", encoded)
        for excluded in ("user_id", "userid", "steam_id", "ticket_hex", "accepted_response", "fields", "hex", "C:\\", "server_echo"):
            self.assertNotIn(excluded, encoded)
        self.assertTrue(result["thirty_minute_soak_verified"])
        self.assertEqual(result["controls"]["fire"]["after"]["local"]["inventory"][0]["clip"], 19)
        self.assertEqual(result["controls"]["fire"]["server_event"]["values"], {"weapon": "glock", "silenced": False})
        self.assertTrue(result["controls"]["say"]["echo_verified"])
        self.assertEqual(result["runtime_full"]["processes"][0]["modules"], [{"name": "steam_api.dll", "sha256": "c" * 64}])
        self.assertIn("reload", result["unverified_controls"])
        self.assertEqual(result["soak"]["measurements"][0]["local"]["eye_angles"], [12, 37])
        self.assertEqual(result["soak"]["activity"], [{"elapsed_seconds": 30, "input": {"forward": 0.35, "yaw": 90, "buttons": ["jump"]}}])

    def test_incomplete_soak_is_not_promoted(self):
        report = self.report()
        report["state"] = "failed"
        report["soak"]["elapsed_seconds"] = 793.172
        report["soak"]["continuous_full"] = False
        report["error"] = "Unexpected server disconnect: AFK spectator kick PRIVATE_AUTH_AND_IDENTITY_SENTINEL"
        report["thirty_minute_soak_verified"] = True
        result = summary.summarize(report, "b" * 64, failure_category="server_afk_rejection")
        self.assertFalse(result["thirty_minute_soak_verified"])
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["failure_category"], "server_afk_rejection")
        report["soak"]["elapsed_seconds"] = 1801
        self.assertFalse(summary.summarize(report, "b" * 64)["thirty_minute_soak_verified"])

    def test_endpoint_and_hash_validation(self):
        report = self.report()
        report["server"] = "127.0.0.1:27015"
        with self.assertRaises(ValueError):
            summary.summarize(report, "b" * 64)
        with self.assertRaises(ValueError):
            summary.summarize(self.report(), "not a hash")
        report = self.report()
        report["profile_sha256"] = "c" * 64
        with self.assertRaises(ValueError):
            summary.summarize(report, "b" * 64)

    def test_nonfinite_and_wrong_types_are_excluded(self):
        report = self.report()
        report["full_signon"]["local"]["position"] = [float("nan"), 2, 3]
        report["full_signon"]["local"]["money"] = True
        result = summary.summarize(report, "b" * 64)
        self.assertNotIn("position", result["full_signon"]["local"])
        self.assertNotIn("money", result["full_signon"]["local"])
        json.dumps(result, allow_nan=False)


if __name__ == "__main__":
    unittest.main()
