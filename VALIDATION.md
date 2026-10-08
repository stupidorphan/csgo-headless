# Validation: Legacy 1.38.8.1 / host 13881

The validation target is exclusively `151.243.93.16:27015`, using a genuine AppID 730 Steam account. Server settings were left unchanged and the SSH key was not used. The profile covers the observed `cs_italy` map and exact pure whitelist; a different map or integrity profile requires a new matching bootstrap.

## Bootstrap evidence

- Matching installation: patch 1.38.8.1, Source revision 8413246, Legacy build 12426195.
- Twelve protobuf file descriptors extracted from the installed binaries; historical reference commit `4ed721cdcc8d828e5dcac3b8d86556e941c804a2`.
- Successful stock signon through the local relay and a finalized demo containing 1,035 playback frames.
- 478 distinct send tables and 284 server classes. Two identical generated array tables were deduplicated.
- Outgoing stock `clc_ClientInfo` send-table CRC: **1008201905**. Map CRC: **920844212**.
- Observed exact 123-byte pure whitelist SHA256 `4e28933eb7ec29379012571cd458724b423ac4eb47e8bade844cfabda31ce04f`.
- 365 distinct captured integrity records over 54 source files, independently checked against actual installed file/chunk MD5s. Runtime uses the resulting integrity metadata.

The relay excluded all connectionless packets, including authentication. Only derived schemas, hashes, provenance, sanitized fixtures, and validation summaries are retained in the repository.

## Offline checks

Debug and Release each pass five CTest suites: wire transport, state/user commands, protobuf parsing, session lifecycle, and the JSON frontend. Eighteen Python metadata/bootstrap tests and four report privacy/evidence tests pass. The frontend suite checks 2,003 correlated responses, bounded queue backpressure, EOF draining, errors, and clean quit without acquiring authentication or opening a live connection.

Coverage includes bounded malformed bitstreams/protobuf, an independent certified ICE-2 vector, folded CRC, Valve LZSS, splitting, reliable loss/retransmission/fragmentation, baselines/entity deltas/handle serials, normalized inventory counts, timed input expiration, user-command encoding, absolute/relative server angle corrections preserving pending controls, complete signon, missing-history recovery, disconnect/reconnect clearing, map transitions, and incompatible metadata rejection. Offline replay sessions cannot acquire a ticket or open a live socket.

Two stock sessions were replayed with the exact profile:

| Session | Packets | Snapshots | Move messages | User commands | Errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| Initial | 1,500 | 531 | 534 | 1,610 | 0 |
| Finalized demo | 2,220 | 944 | 935 | 2,820 | 0 |

All 4,430 commands re-encoded bit for bit. The finalized replay contained two genuine missing-history requests; no decoding errors occurred. See `validation/offline_replay.json` for hashes and measured counters. Committed sanitized fixtures preserve selected stock move messages after raw captures are removed.

## Build and runtime checks

Dependencies are SHA256 pinned in `dependencies.lock.json`. Release client and helper binaries match a clean rebuild byte for byte in the same source/build location. Debug client and helper binaries also match across two clean builds, using embedded debug information. Both comparisons are recorded in `validation/build_reproducibility.json`. This comparison does not claim identical results across arbitrary compiler versions, source locations, or debug PDBs.

The protocol core imports Windows networking/cryptography/kernel libraries. The authentication helper imports the generic Steamworks runtime. Static runtime file-path inspection found the derived profile read and helper launch, with no CS:GO engine or asset paths. Development capture decoding opens capture files only when explicitly selected.

The sustained Release test ran from an isolated package directory with the stock game closed. Loaded-module checks at start, `FULL`, and completion found no stock process, CS:GO engine DLL, or module from the installed game directory. The tested client SHA256 is `b42d693bb49cf5b6e2b00b5760b6cd517dafc968fc91fee998da87264997b1d1`; its profile SHA256 is `3e6b663c5e8e6e7955c4be3f82ba60679f9b4d7b74c9de32c86896da672365c1`. Both hashes are preserved in the runtime and source delivery metadata.

A separate native file-open audit of the extracted Release ZIP passed: **336 calls** across the client and helper, **zero opens under the game installation**, and **zero identified game-directory modules**. All five relative calls were accounted for: one resolved filesystem path and four positively identified unnamed pipes, with zero unresolved filesystem roots. The client reached `FULL`, ran for 45 seconds, and disconnected cleanly with the stock game closed. See `validation/runtime_file_audit.json` for paths, handle classification, provenance, counters, and coverage.

The auditor's offline parent/child positive control also passed: 180 calls, 12 synthetic asset opens caught, six relative filesystem calls resolved, six unnamed pipe calls positively identified, and zero unresolved roots. See `validation/runtime_file_audit_fixture.json`.

This audit intercepts native `NtCreateFile`/`NtOpenFile` arguments after the debugger's initial breakpoint and snapshots loaded modules. It does not measure read lengths, intercept earlier startup opens or direct system calls bypassing those exports, or cover the separate Steam client process. Unknown filesystem roots prevent verification; only positively identified pipe/device handles with empty names are classified as non-filesystem.

Three CDB image records lacked absolute filenames, so their origin remains unclassified in that report. The independent module inspections during the 30-minute run recorded full module paths and found no game-directory or engine DLLs. The final delivery uses the same executable, helper, Steam runtime, and profile hashes as the extracted package audit; finalized instructions and reports are added to the ZIP afterward.

## Live acceptance

The final Release run reached `FULL` in **4.375 seconds**, selected T, and spawned with health 100. All 13 checks passed: inventory, use, buying, weapon switching, aiming, movement, input expiry, jumping, crouching, firing, reloading, public chat, and team chat. Control responses alone were not counted as proof; subsequent snapshots and matching server events confirmed the effects.

Examples include armor changing from 0 to 100 and money from 800 to 150 after buying, replicated eye angles near the requested 12/40 degrees, increased jump height and duck amount, a Glock magazine decreasing from 20 to 19 on firing, and a reload event followed by a full 20-round magazine. Use produced the server's buy-menu command; both chat commands produced matching server echoes.

The uninterrupted soak lasted **1,800.032 seconds** at `FULL`, with 60 measured samples. Server tick advanced from **853063 to 968265**, and received packets from **1,317 to 116,517**. The player finished alive with health 100 after 13 rounds. The full run, including signon, gameplay checks, and clean shutdown, lasted 1,823.828 seconds. No controls remained unverified.

The soak used 60 predetermined movement/view inputs, one every 30 seconds. It made no autonomous gameplay decisions and kept the server's settings unchanged. An earlier idle attempt ended after 793.172 seconds when the server enforced its AFK spectator policy; it is retained separately as a failed trial in `validation/live_idle_trial_13881.json` and is not counted toward the successful duration.

`validation/live_13881.json` retains the quantitative control snapshots, events, timings, module hashes, and soak counters. Its allowlist excludes account/player identifiers, chat contents, raw fields, and diagnostic text. Raw stock demos/captures and local live JSON logs are removed after deriving and checking the retained evidence.
