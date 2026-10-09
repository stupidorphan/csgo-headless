# Standalone CS:GO Legacy client

C++20 Windows implementation for Legacy 1.38.8.1, host version 13881. A genuine Steam account supplies AppID 730 session tickets through an in-process Steam CM/authentication implementation. The client does not require `steam.exe`, `steam_api.dll`, CS:GO engine DLLs, maps, models, or other game assets.

The supplied metadata profile covers `151.243.93.16:27015`, `cs_italy`, and its observed pure whitelist. Changed maps, checksums, or integrity requirements require another verified profile. Server settings are not changed by this client.

## Build

Use Visual Studio 2022 with C++ desktop tools, Windows SDK, and CMake 3.25 or newer. The client builds for Win32 and x64; the Legacy wire protocol is independent of the host pointer width.

The validated toolchain is CMake 3.31.6-msvc6, MSVC 19.44.35228.0 (v143, tools directory 14.44.35207), and Windows SDK 10.0.26100.0. `dependencies.lock.json` pins the JSON and QR encoder sources/licenses by SHA256. Configuration rejects changed dependency contents. MSVC compilation and linking use `/Brepro`, with incremental linking disabled; binary reproducibility was checked by clean rebuilds in the same source/build location.

Git attributes fix source line endings and preserve the exact verified profile and pinned dependency bytes. The source archive therefore retains the same profile SHA256 as the tested runtime package.

```powershell
cmake --preset windows
cmake --build --preset debug
ctest --preset debug
cmake --build --preset release
ctest --preset release
cmake --build --preset release-x64
ctest --preset release-x64
python tests/metadata_tests.py
```

The x64 preset configures `build-x64` and produces `build-x64/Release/headless-csgo.exe`. The native file-open audit remains an x86-only diagnostic because it uses the installed x86 CDB debugger; it is not part of the x64 CTest target set.

JSON for Modern C++ 3.12.0 and Nayuki's MIT QR encoder are vendored with exact SHA256 entries in `dependencies.lock.json`. Release output contains only the client, derived metadata, documentation, and examples. The first login creates `steam-accounts.json` plus one current-user-only token file per account beside the executable. Token files are written atomically; keep them private and back them up only through a protected user-managed location.

## Interactive control

From an extracted package directory:

```powershell
.\headless-csgo.exe --interactive --profile profiles/legacy_13881.json
```

From the source checkout, use `.\build\Release\headless-csgo.exe --interactive --profile profiles/legacy_13881.json` instead.

```text
login qr
# scan the URL/matrix with the Steam mobile app, then wait for auth_completed
list
use 1
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

`login` creates or selects an account and starts QR or password authentication (`login 2 password` selects an existing account; `login qr` creates the next account). `list` reports account IDs, labels, token availability, Steam IDs, and the active account. `use ACCOUNT` switches the active account while disconnected. One process owns one active gameplay connection; switching while connected is rejected so tickets and server state cannot be mixed. `connect [IP:PORT]` accepts an endpoint argument, subject to the verified metadata profile and its authorized server coverage. `say hello` and the other gameplay commands use the active account.

`auth password` remains an alias for authenticating the active account and emits ephemeral prompts for the Steam account name, password, email code, TOTP, or mobile confirmation. In interactive mode, enter the account name at the account prompt and then enter each secret on its own hidden line. JSON clients submit `auth_input` with the prompt ID and value; secrets are never echoed by the client or included in status events. `auth logout` closes the CM session and clears in-memory tokens while leaving the user-managed token file in place. A token file is reused on the next start when its access token is still valid; an expired access token is renewed with the stored refresh token.

`weapon` takes an entity index from the server-confirmed inventory. Purchase success depends on the server's game mode, team, money, and buy zone. `team` accepts `T`, `CT`, or `spectator`.

`input` accepts `forward`, `side`, and `up` in [-1,1], `pitch` and `yaw` in degrees, a `buttons` array, and `duration_ticks`. Axes and buttons return to zero after the requested number of server ticks; view angles persist. A new `input` replaces pending movement and buttons. Button names include `attack`, `attack2`, `jump`, `duck`, `use`, `reload`, and `walk`. Server fixes may replace the view angles. `aim PITCH YAW` and `move FORWARD SIDE TICKS` are interactive shortcuts. View-only input does not wait for local prediction; inspect `status` for the confirmed result.

## JSON stdio

```powershell
.\headless-csgo.exe --json --profile profiles/legacy_13881.json
python examples/control.py .\headless-csgo.exe
```

From the source checkout, the corresponding executable is `.\build\Release\headless-csgo.exe`.

One request per line:

```json
{"id":1,"op":"login","args":{"mode":"qr"}}
{"id":2,"op":"list","args":{}}
{"id":3,"op":"use","args":{"account":1}}
{"id":4,"op":"connect","args":{"server":"151.243.93.16:27015"}}
{"id":5,"op":"say","args":{"text":"hello"}}
{"id":6,"op":"status","args":{}}
```

Responses echo `id` and contain `ok` plus `result` or `error`. Auth events are `auth_qr`, `auth_qr_refresh`, `auth_prompt`, `auth_state`, `auth_completed`, and `auth_error`; QR events include the URL, a Unicode matrix for JSON consumers, and an ASCII-safe matrix used by the interactive terminal. Asynchronous gameplay events include `type` and server `tick`. Protocol diagnostics go to stderr; `--trace` enables message summaries without authentication tickets. `status` exposes signon state, packet counts, map/ticks, local player, players, inventory, and round information. Positions come from decoded server snapshots. A missing delta history sends tick -1 until a full snapshot restores state.

Gameplay responses acknowledge queuing the request. A subsequent snapshot or game event confirms its effect. Inventory `clip` values are magazine counts (`-1` means no magazine); `fields` retains the original network properties. `server_command` events surface commands sent by the server, such as `buymenu` in response to use in a buy zone. They are informational and do not execute terminal commands. Leave at least 0.66 seconds between chat requests to satisfy the game's shared public/team chat cooldown. Allow a drawn weapon to finish deploying before sending a short firing input.

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

No rendering, voice, matchmaking, CS2, autonomous decision making, or collision prediction. Multiple stored accounts are supported, with one active gameplay connection per process. Timing and controls use the server tick interval; gameplay state remains server-authoritative. Authentication failures, unsupported connection features, profile mismatches, server rejection, and timeouts are reported explicitly. Disconnect clears session state and pending input, and cancels the Steam ticket.

See `VALIDATION.md` for the measured validation results.

## Validation and packages

The live harness only accepts the authorized endpoint. With an existing `steam-auth.json`, it checks stock processes, loaded modules, server-confirmed controls, and continuous `FULL` with tick and packet progress:

```powershell
python tools/validate_live.py build/Release/headless-csgo.exe --seconds 1800
python tools/validate_live.py build/Release/headless-csgo.exe --auth-qr --seconds 1800
```

During the soak, the harness sends a fixed four-direction movement/view script every 30 seconds. This keeps a normal player active under the server's AFK policy; it makes no autonomous gameplay decisions. Use `--activity-seconds 0` for an idle soak. This server rejected the earlier idle attempt under its existing AFK policy.

After the run, retain a derived report and remove the local raw JSON log:

```powershell
python tools/summarize_live_validation.py artifacts/live/RUN/validation.json --output validation/live_13881.json
```

The summary keeps measured state, counters, control effects, and module hashes while excluding player/account identifiers, chat contents, and raw messages.

`tests/fixtures` retains sanitized stock user commands; `validation` contains derived reports. Build outputs, raw captures, demos, and credentials are excluded from Git.

`tools/audit_runtime_files.py` uses an existing x86 Windows SDK CDB debugger to follow native file opens and DLLs in the client. It retains paths and verification counters, with no packet or ticket contents. Run it separately from other live clients after authenticating the client. Supply absolute executable/profile paths because its working directory is the audit output folder:

```powershell
python tools/audit_runtime_files.py --output artifacts/file-audit --game-root "D:/SteamLibrary/steamapps/common/Counter-Strike Global Offensive" --require-full -- C:/absolute/package/headless-csgo.exe --json --connect --run-seconds 45 --profile C:/absolute/package/profiles/legacy_13881.json
```

The `file-audit-fixture` build target supplies an offline parent/child positive control for that auditor; it opens only a supplied synthetic fixture file. The auditor report states its coverage limits, including file opens before the debugger's initial breakpoint.

```powershell
python tools/package_release.py --configuration Release
python tools/package_release.py --configuration Debug
```

Packages include the client, exact profile/descriptors, instructions, Python example, dependency notices, derived offline validation metadata, and a SHA256 manifest. Packaging uses fixed archive timestamps and an explicit file allowlist. Extract a package into its own directory, authenticate with `auth qr` or `auth password`, and run the interactive or JSON commands above there.

The separate source ZIP contains the C++ implementation, metadata-generation tools, tests, and sanitized fixtures. Create it from the committed checkout after recording the validation results:

```powershell
git archive --format=zip --output=artifacts/release/headless-csgo-13881-source.zip HEAD
```

Building from source requires only the Windows toolchain and the vendored pinned sources. Steam authentication contacts Steam's authentication service and CM at runtime; no Steam client or installed game files are build or runtime inputs.
