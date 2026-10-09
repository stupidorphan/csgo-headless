# Validation: Legacy 1.38.8.1 / host 13881

The gameplay metadata is restricted to `151.243.93.16:27015`; no SSH connection was used. The profile covers the observed `cs_italy` map, send-table checksum, entity schema, pure whitelist, and integrity records derived from the matching Legacy installation. Raw captures, tickets, credentials, and game files are excluded.

## Offline checks

The Debug CTest suite passes six tests: wire transport, state/user commands, protobuf parsing, session lifecycle, native-auth/QR behavior, and the JSON frontend. The Python metadata, bootstrap, privacy, and summary tests pass. Checks cover malformed bitstreams/protobuf, ICE-2, CRC/LZSS, splitting, reliable retransmission and fragmentation, entity deltas, timed inputs, user-command encoding, complete signon, snapshot recovery, disconnect/reconnect clearing, map transitions, auth prompt routing, QR rendering, invalid token-file handling, and package privacy.

Replay sessions remain offline-only and cannot acquire a Steam ticket or open a live socket. The existing sanitized replay fixtures still re-encode captured move messages bit for bit against the verified profile.

## Native authentication checks

The client no longer links Steamworks or launches another process for authentication. CNG RSA PKCS#1 encryption, bounded WinHTTP authentication responses, atomic token-file replacement, current-user-only ACL application, QR refresh rendering, prompt routing, WebSocket CM framing, heartbeats, reconnect state, AppID 730 ownership-ticket requests, game-connect-token consumption, SteamKit-compatible type-2 ticket layout, CRC acknowledgement correlation, ticket combination, and ticket zeroization paths are covered by code review and offline fixtures. The CM and authentication code requires a real Steam account for end-to-end validation; no credentials or token file are committed.

## Build and runtime checks

The Win32 Debug build succeeds with the Visual Studio 2022 toolchain and no Steam SDK inputs. CMake validates only the pinned nlohmann/json and Nayuki QR encoder files. The release package contains the client, profile, derived descriptors, documentation, examples, and licenses. It contains no `steam.exe`, `steam_api.dll`, Steamworks import library, second authentication executable, CS:GO engine DLL, or installed asset.

The existing native file-open audit remains available for the standalone executable. A new live audit should be run after native authentication is exercised; it must confirm that the stock game and Steam client remain closed and that no game-directory modules are loaded.

## Live acceptance

Live Steam QR/password authentication and the 30-minute gameplay soak have not been rerun after introducing native authentication. They require the account owner to complete a QR or password/Steam Guard prompt. Once authenticated, run the existing live harness exclusively against `151.243.93.16:27015` and retain only its sanitized derived report:

```powershell
python tools/validate_live.py build/Release/headless-csgo.exe --seconds 1800
python tools/validate_live.py build/Release/headless-csgo.exe --auth-qr --seconds 1800
```

The live run must reach `FULL`, join/spawn, verify server-confirmed movement, aiming, firing, reloading, buying, chat, reconnect with a renewed ticket, and complete 1,800 seconds without opening the stock game or Steam client. Until that run is performed, the native-auth implementation is build- and offline-validated but not live-certified.
