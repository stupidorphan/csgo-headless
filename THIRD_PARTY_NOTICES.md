# Third-party components

The vendored `third_party/nlohmann/json.hpp` is JSON for Modern C++ v3.12.0, Copyright Niels Lohmann, distributed under the MIT license included in the header. Its SHA-256 is `aaf127c04cb31c406e5b04a63f1ae89369fccde6d8fa7cdda1ed4f32dfc5de63`.

The Steam authentication helper uses locally supplied Steamworks SDK headers, an import library, and the Steamworks API redistributable. Those components retain Valve's terms and are not committed here. No CS:GO engine or asset binaries are distributed in this repository.

Protocol metadata is derived from the user-provided matching Legacy installation. The historical public SteamTracking protobuf baseline is commit `4ed721cdcc8d828e5dcac3b8d86556e941c804a2`; the installed descriptors are the authority for this profile.
