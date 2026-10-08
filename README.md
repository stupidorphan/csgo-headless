# Standalone CS:GO Legacy client

C++20 Windows implementation for Legacy 1.38.8.1, host version 13881. A genuine logged-in Steam account supplies AppID 730 session tickets through a separate Steamworks helper. The protocol core does not load CS:GO engine DLLs, maps, models, or other assets.

The supplied metadata profile covers `151.243.93.16:27015`, `cs_italy`, and its observed pure whitelist. Changed maps, checksums, or integrity requirements require another verified profile. Server settings are not changed by this client.

## Build

Use Visual Studio 2022 with C++ desktop tools, Windows SDK, and CMake 3.24 or newer. The current helper uses the locally available 32-bit Steamworks SDK, so configure Win32.

```powershell
cmake --preset windows -DSTEAM_SDK_DIR="E:/archives/csgo/csgo_partner/src" -DSTEAM_API_DLL="D:/SteamLibrary/steamapps/common/Counter-Strike Global Offensive/bin/steam_api.dll"
cmake --build --preset debug
ctest --preset debug
cmake --build --preset release
ctest --preset release
python tests/metadata_tests.py
```

JSON for Modern C++ 3.12.0 is vendored with its exact SHA256 in `THIRD_PARTY_NOTICES.md`. The helper alone links the locally supplied Steamworks SDK. Build output includes `steam_auth_helper.exe`, the generic `steam_api.dll` redistributable, and `steam_appid.txt`; keep these beside `headless-csgo.exe`. Runtime needs Steam running and signed in, with the stock game closed.

## Interactive control

From the project or packaged directory:

```powershell
.\headless-csgo.exe --interactive --profile profiles/legacy_13881.json
```

```text
connect
status
team T
input {"forward":1,"pitch":0,"yaw":90,"buttons":["jump"],"duration_ticks":32}
input {"buttons":["attack"],"duration_ticks":8}
input {"buttons":["reload"],"duration_ticks":1}
input {"buttons":["duck","use"],"duration_ticks":8}
weapon 125
buy ak47
say hello
say_team ready
disconnect
quit
```

`weapon` takes an entity index from the server-confirmed inventory. Purchase success depends on the server's game mode, team, money, and buy zone. `team` accepts `T`, `CT`, or `spectator`.

`input` accepts `forward`, `side`, and `up` in [-1,1], `pitch` and `yaw` in degrees, a `buttons` array, and `duration_ticks`. Axes and buttons return to zero after the requested number of outgoing server ticks; view angles persist. Button names include `attack`, `attack2`, `jump`, `duck`, `use`, `reload`, and `walk`. Server fixes may replace the view angles. `aim PITCH YAW` and `move FORWARD SIDE TICKS` are interactive shortcuts.

## JSON stdio

```powershell
.\headless-csgo.exe --json --profile profiles/legacy_13881.json
python examples/control.py .\headless-csgo.exe
```

One request per line:

```json
{"id":1,"op":"connect","args":{}}
{"id":2,"op":"team","args":{"team":"T"}}
{"id":3,"op":"input","args":{"forward":1,"yaw":90,"duration_ticks":32}}
{"id":4,"op":"status","args":{}}
```

Responses echo `id` and contain `ok` plus `result` or `error`. Asynchronous events include `type` and server `tick`. Protocol diagnostics go to stderr; `--trace` enables message summaries without authentication tickets. `status` exposes signon state, packet counts, map/ticks, local player, players, inventory, and round information. Positions come from decoded server snapshots. A missing delta history sends tick -1 until a full snapshot restores state.

## Development bootstrap

These tools may read the matching installation during development. Their derived profile is the runtime input.

```powershell
python tools/extract_metadata.py --game "D:/SteamLibrary/steamapps/common/Counter-Strike Global Offensive" --output profiles/legacy_13881.json
python tools/bootstrap_relay.py --capture artifacts/bootstrap/session.jsonl --duration 300
```

In a second terminal, record the genuine stock session:

```powershell
python tools/stock_bootstrap.py --game "D:/SteamLibrary/steamapps/common/Counter-Strike Global Offensive" --seconds 30
```

The relay binds `127.0.0.2:27016` and forwards exclusively to the authorized server. It excludes all connectionless packets, including authentication. The bootstrap tool controls the stock client through Source's password-protected netconsole. It starts recording during signon and disconnects to finalize the buffered demo. It does not alter server settings. Close other stock instances before running it.

```powershell
.\build\Release\headless-csgo.exe --decode-capture artifacts/bootstrap/session.jsonl artifacts/bootstrap/metadata.json
python tools/extract_profile.py --profile profiles/legacy_13881.json --demo "D:/SteamLibrary/steamapps/common/Counter-Strike Global Offensive/csgo/codex_headless_bootstrap.dem" --client-info artifacts/bootstrap/metadata.json --game "D:/SteamLibrary/steamapps/common/Counter-Strike Global Offensive" --bsp "D:/SteamLibrary/steamapps/common/Counter-Strike Global Offensive/csgo/maps/cs_italy.bsp" --stock-signon-verified
```

The extractor checks the actual outgoing `clc_ClientInfo` checksum, demo entity schema, map checksum, pure whitelist SHA256, and captured file hashes against the installed files. It preserves descriptive schemas, hashes, integrity metadata, and provenance. Keep raw demos and packet captures local and uncommitted; remove them once derived evidence is verified. Tickets and secrets are never profile inputs. The SSH key is not used.

## Scope

No rendering, voice, matchmaking, CS2, autonomous decision making, collision prediction, or multiple accounts. Timing and controls use the server tick interval; gameplay state remains server-authoritative. Authentication failures, unsupported connection features, profile mismatches, server rejection, and timeouts are reported explicitly. Disconnect clears session state and pending input, and cancels the Steam ticket.

See `VALIDATION.md` for the measured validation results.
