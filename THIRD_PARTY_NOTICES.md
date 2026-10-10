# Third-party components

The vendored `third_party/nlohmann/json.hpp` is [JSON for Modern C++ v3.12.0](https://github.com/nlohmann/json/releases/tag/v3.12.0), Copyright (c) 2013-2025 Niels Lohmann. Its SHA-256 is `aaf127c04cb31c406e5b04a63f1ae89369fccde6d8fa7cdda1ed4f32dfc5de63`. The complete MIT license is copied to [`third_party/nlohmann/LICENSE.MIT`](third_party/nlohmann/LICENSE.MIT).

The vendored `third_party/qrcodegen` sources are Nayuki's QR Code generator library, pinned to commit [`3c6d0b3cefb4e049dc337e82237c9644399716a8`](https://github.com/nayuki/QR-Code-generator/tree/3c6d0b3cefb4e049dc337e82237c9644399716a8). The library is MIT licensed; its license is copied to [`third_party/qrcodegen/LICENSE.MIT`](third_party/qrcodegen/LICENSE.MIT). Exact source and license hashes are recorded in [`dependencies.lock.json`](dependencies.lock.json).

Steam CM multi-message payload decompression uses Joergen Ibsen's tiny inflate library (`tinf`), Copyright (c) 2003-2019 Joergen Ibsen, distributed under the zlib license.

The client uses Windows CNG, WinHTTP, and the Windows ACL APIs supplied by the operating system. It does not link Steamworks, load `steam_api.dll`, launch `steam.exe`, or require CS:GO engine or asset files. Steam authentication is implemented in-process from the public SteamKit2 protocol behavior; no SteamKit2 binaries or source files are redistributed.

Protocol metadata is derived from the user-provided matching Legacy installation. The historical public SteamTracking protobuf baseline is commit `4ed721cdcc8d828e5dcac3b8d86556e941c804a2`; installed descriptors are the authority for the runtime profile. Derived metadata contains hashes and schemas, not credentials, tickets, raw captures, or game files.
