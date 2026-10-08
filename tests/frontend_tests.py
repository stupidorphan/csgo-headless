"""Offline process checks for bounded JSON input and response correlation."""
import json
from pathlib import Path
import subprocess
import sys

exe, profile = map(lambda value: str(Path(value).resolve()), sys.argv[1:3])
requests = [{"id": index, "op": "status", "args": {}} for index in range(2000)]
requests += [{"id": "bad-arguments", "op": "status", "args": []},
             {"id": "unknown-operation", "op": "unknown", "args": {}},
             {"id": "quit", "op": "quit", "args": {}}]
stdin = "\n".join(json.dumps(value) for value in requests) + "\n"
completed = subprocess.run([exe, "--json", "--profile", profile], input=stdin,
                           capture_output=True, text=True, timeout=60, check=True)
responses = [json.loads(line) for line in completed.stdout.splitlines()]
assert len(responses) == len(requests), (len(responses), len(requests))
assert [response["id"] for response in responses] == [request["id"] for request in requests]
assert all(response["ok"] and response["result"]["connection"]["state"] == "disconnected" for response in responses[:2000])
assert not responses[-3]["ok"] and not responses[-2]["ok"] and responses[-1]["ok"]
assert not completed.stderr, completed.stderr

completed = subprocess.run([exe, "--json", "--profile", profile], input="{invalid}\n",
                           capture_output=True, text=True, timeout=30, check=True)
error = json.loads(completed.stdout)
assert error["type"] == "response" and error["id"] is None and not error["ok"]
print("JSON frontend passed: 2003 correlated requests, queue backpressure, EOF drain, errors, clean quit; no live connection")
