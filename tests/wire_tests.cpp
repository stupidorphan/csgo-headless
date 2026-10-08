#include "hc/netchannel.hpp"
#include "hc/wire.hpp"
#include "hc/proto.hpp"
#include "hc/usercmd.hpp"

#include <algorithm>
#include <array>
#include <functional>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <nlohmann/json.hpp>

namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
void rejects(const std::function<void()>& action, const char* message) {
    try { action(); } catch (const hc::WireError&) { return; }
    throw std::runtime_error(message);
}
hc::Bytes text_bytes(const std::string& text) { return {text.begin(), text.end()}; }
hc::Bytes packet(std::uint32_t sequence, std::uint32_t ack, std::uint8_t state, const hc::Bytes& body = {}, unsigned body_bits = 0, bool reliable = false) {
    hc::BitWriter writer;
    writer.bits(sequence, 32); writer.bits(ack, 32); writer.bits(0, 8); writer.bits(0, 16); writer.bits(state, 8);
    if (!body_bits) body_bits = static_cast<unsigned>(body.size() * 8);
    writer.bit_bytes(body, body_bits);
    const unsigned pad = static_cast<unsigned>((8 - (writer.position() & 7)) & 7);
    if (pad) writer.bits((1u << pad) - 1, pad);
    auto result = writer.take();
    result[8] = static_cast<std::uint8_t>((reliable ? 1 : 0) | (pad << 5));
    const auto crc = hc::short_checksum(std::span(result).subspan(11));
    result[9] = static_cast<std::uint8_t>(crc); result[10] = static_cast<std::uint8_t>(crc >> 8);
    return result;
}
void bitstreams() {
    hc::BitWriter writer;
    writer.bits(5, 3); writer.signed_bits(-7, 9); writer.float32(12.25f);
    writer.varuint32(0xffffffffu); writer.varuint64(0xffffffffffffffffull);
    for (auto value : {0u, 15u, 16u, 255u, 256u, 4095u, 4096u, 0xffffffffu}) writer.ubitvar(value);
    writer.string("unaligned"); writer.bytes(std::array<std::uint8_t, 3>{0, 128, 255});
    const auto count = writer.position();
    hc::BitReader reader(writer.data(), count);
    require(reader.bits(3) == 5 && reader.signed_bits(9) == -7, "signed unaligned bits");
    require(reader.float32() == 12.25f, "unaligned float");
    require(reader.varuint32() == 0xffffffffu && reader.varuint64() == 0xffffffffffffffffull, "varint maximum values");
    for (auto value : {0u, 15u, 16u, 255u, 256u, 4095u, 4096u, 0xffffffffu}) require(reader.ubitvar() == value, "UBitVar boundary");
    require(reader.string() == "unaligned", "NUL string");
    require(reader.bytes(3) == hc::Bytes({0, 128, 255}) && reader.empty(), "unaligned bytes");
    rejects([&] { reader.bit(); }, "truncated read accepted");
    rejects([&] { reader.seek(count + 1); }, "oversized seek accepted");
    rejects([&] { const hc::Bytes data{128,128,128,128,16}; hc::BitReader bad(data); bad.varuint32(); }, "varint32 overflow accepted");
    rejects([&] { const hc::Bytes data{128}; hc::BitReader bad(data); bad.varuint64(); }, "unterminated varint accepted");
    rejects([&] { hc::BitWriter bad(1); bad.bits(0, 9); }, "writer capacity accepted");
    rejects([&] { const hc::Bytes data{'x'}; hc::BitReader bad(data); bad.string(); }, "unterminated string accepted");
    hc::BitWriter golden;
    golden.bits(5, 3); golden.bits(0xa5, 8); golden.bits(3, 2);
    require(golden.data() == hc::Bytes({0x2d, 0x1d}), "LSB bit packing golden vector");
    require(hc::crc32(text_bytes("123456789")) == 0xcbf43926u, "IEEE CRC32 certification vector");
    require(hc::short_checksum(text_bytes("123456789")) == 0xf2d2, "Source folded checksum");
}
void encryption() {
    // Matthew Kwan's independent ICE-2 certification triplet:
    // https://darkside.com.au/ice/overview.html
    const std::array<std::uint8_t, 16> key{0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    const hc::Bytes plain{0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    const hc::Bytes cipher{0xf9,0x48,0x40,0xd8,0x69,0x72,0xf2,0x1c};
    const hc::IceCipher ice(key);
    require(ice.encrypt(plain) == cipher && ice.decrypt(cipher) == plain, "ICE-2 certification vector");
    const std::array<std::uint8_t, 16> expected{'C','S','G','O',57,54,0,0,142,13,0,0,99,3,0,0};
    require(hc::default_ice_key(13881) == expected, "host version key derivation");
    for (std::size_t size = 1; size < 200; ++size) {
        hc::Bytes input(size, static_cast<std::uint8_t>(size));
        const auto encrypted = hc::encrypt_envelope(input, expected);
        require(encrypted.size() % 8 == 0 && hc::decrypt_envelope(encrypted, expected) == input, "ICE packet envelope");
    }
    rejects([&] { ice.decrypt(hc::Bytes{1}); }, "ICE unaligned block accepted");
    rejects([&] { hc::decrypt_envelope(hc::Bytes(8, 0), expected); }, "invalid ICE envelope accepted");
    hc::Bytes malformed(24, 0); malformed[0] = 19;
    rejects([&] { hc::decrypt_envelope(ice.encrypt(malformed), key); }, "empty envelope payload accepted");
}
void compression() {
    const hc::Bytes golden{'L','Z','S','S',8,0,0,0,12,'A','B',0,0x15,0,0};
    require(hc::lzss_decompress(golden) == text_bytes("ABABABAB"), "LZSS overlapping match vector");
    std::mt19937 random(24);
    for (unsigned n = 0; n < 80; ++n) {
        hc::Bytes data(n * 37);
        for (auto& byte : data) byte = static_cast<std::uint8_t>(random() % (n & 1 ? 8 : 256));
        require(hc::lzss_decompress(hc::lzss_compress(data), data.size()) == data, "LZSS random round trip");
    }
    rejects([&] { hc::lzss_decompress(golden, 7); }, "LZSS oversized output accepted");
    auto bad = golden; bad[11] = 1;
    rejects([&] { hc::lzss_decompress(bad); }, "LZSS preceding-output reference accepted");
    bad = golden; bad.resize(12);
    rejects([&] { hc::lzss_decompress(bad); }, "LZSS truncation accepted");
    bad = golden; bad[4] = 7;
    rejects([&] { hc::lzss_decompress(bad); }, "LZSS advertised size overflow accepted");
}
void framing() {
    const hc::Message source{130, hc::Bytes{3,4,5}, true};
    const auto encoded = hc::encode_message(source);
    require(encoded == hc::Bytes({0x82,1,3,3,4,5}), "protobuf frame golden vector");
    hc::BitWriter unaligned;
    unaligned.bits(5, 3); unaligned.bytes(encoded);
    hc::BitReader reader(unaligned.data(), unaligned.position()); reader.skip(3);
    const auto decoded = hc::decode_messages(reader, true);
    require(decoded.size() == 1 && decoded[0].type == source.type && decoded[0].bytes == source.bytes && decoded[0].reliable, "unaligned protobuf framing");
    rejects([&] { const hc::Bytes data{1,10,0}; hc::BitReader bad(data); hc::decode_messages(bad); }, "oversized protobuf frame accepted");
}
void transport() {
    hc::ChannelConfig plain; plain.encryption = false;
    // Installed 13881 capture proves the single-block size is 20 bits. This
    // fixed unaligned body decodes as type 6 / length 4 only at that width.
    hc::Netchannel legacy(plain);
    const hc::Bytes legacy_body{0x88,0x01,0x00,0x18,0x10,0x28,0x08,0x20,0x04,0xf8};
    const auto legacy_packet = legacy.receive(packet(1,0,0,legacy_body,75,true));
    require(legacy_packet.valid && legacy_packet.messages.size() == 1 && legacy_packet.messages[0].type == 6 && legacy_packet.messages[0].bytes == hc::Bytes({10,2,8,1}), "13881 single-block 20-bit size fixture");
    hc::Netchannel golden(plain);
    require(golden.send().front() == hc::Bytes({1,0,0,0,0,0,0,0,0,0x3f,0x31,0,0,0,0,0}), "unreliable header/checksum golden vector");
    for (const bool encrypted : {false, true}) {
        auto config = plain; config.encryption = encrypted;
        hc::Netchannel client(config), server(config);
        hc::Message first{8, hc::Bytes(33, 0xab), true}; client.queue(first);
        auto received = server.receive(client.send().front());
        require(received.valid && received.messages.size() == 1 && received.messages[0].bytes == first.bytes, "single-block reliable delivery");
        require(client.receive(server.send().front()).valid && !client.pending_reliable(), "reliable acknowledgment");
        const std::array<hc::Message, 1> moves{hc::Message{9, hc::Bytes{1,2,3}, false}};
        auto outgoing = client.send(moves);
        received = server.receive(outgoing.front());
        require(received.valid && received.messages.size() == 1 && !received.messages[0].reliable && received.messages[0].type == 9, "unreliable frame delivery");
        require(!server.receive(outgoing.front()).valid, "duplicate sequence accepted");
        auto corrupt = outgoing.front(); corrupt.back() ^= 0x80;
        require(!server.receive(corrupt).valid, "corrupt packet accepted");
    }
    // Loss of the transfer header causes later groups to be rejected and both
    // groups to be retransmitted once the peer acknowledges their sequences.
    hc::Netchannel client(plain), server(plain);
    hc::Message large{8, hc::Bytes(2000, 0xab), true}; client.queue(large);
    client.send(); // lost
    require(!server.receive(client.send().front()).valid, "headerless fragment group accepted");
    require(client.receive(server.send().front()).valid, "negative fragment acknowledgment");
    auto received = server.receive(client.send().front());
    require(received.valid && received.messages.empty(), "first fragment retry");
    received = server.receive(client.send().front());
    require(received.valid && received.messages.size() == 1 && received.messages[0].bytes == large.bytes, "fragment loss recovery");
    require(client.receive(server.send().front()).valid && !client.pending_reliable(), "multi-subchannel acknowledgment");
    client.reset(); server.reset();
    const std::array<hc::Message, 1> giant{hc::Message{9, hc::Bytes(5000, 0x51), false}};
    auto split = client.send(giant);
    require(split.size() > 1, "UDP split not generated");
    for (std::size_t i = split.size(); i-- > 0;) {
        received = server.receive(split[i]);
        require(i == 0 ? received.valid : received.pending, "out-of-order UDP reassembly");
        if (i == split.size() - 1) require(server.receive(split[i]).pending, "duplicate UDP part changed completion");
    }
    require(received.messages.size() == 1 && received.messages[0].bytes == giant[0].bytes, "split packet payload");
    client.reset(); server.reset();
    // Reliable packets with seven fragments force outer UDP splitting as well.
    auto split_config = plain; split_config.reliable_fragments_per_packet = 7;
    hc::Netchannel a(split_config), b(split_config);
    a.queue(hc::Message{8, hc::Bytes(1700, 3), true});
    auto parts = a.send(); require(parts.size() == 2, "reliable UDP split count");
    require(b.receive(parts[1]).pending, "reliable split waits for all parts");
    received = b.receive(parts[0]);
    require(received.valid && received.messages.size() == 1 && received.messages[0].bytes.size() == 1700, "reliable split frame delivery");
    // Capture readers do not confuse recorded ACKs with their own unsent state.
    auto passive_config = plain; passive_config.passive = true;
    hc::Netchannel passive(passive_config);
    require(passive.receive(packet(1, 1234, 0, hc::encode_message(hc::Message{8,{1},false}))).valid, "passive capture ACK handling");
    require(!client.receive(packet(1, 1234, 0)).valid, "future acknowledgment accepted");
    require(client.receive(hc::Bytes{255,255,255,255,'A'}).connectionless, "connectionless routing");
    require(!client.receive(hc::Bytes{254,255,255,255,0}).valid, "truncated split accepted");
}
void malformed_transfer() {
    hc::ChannelConfig config; config.encryption = false;
    hc::Netchannel channel(config);
    hc::BitWriter body;
    body.bits(0, 3); body.bit(true); body.bit(true); body.bits(1, 18); body.bits(7, 3); body.bit(false);
    require(!channel.receive(packet(1,0,0,body.data(),static_cast<unsigned>(body.position()),true)).valid, "headerless malicious fragment accepted");
    channel.reset();
    hc::BitWriter oversized;
    oversized.bits(0,3); oversized.bit(true); oversized.bit(true); oversized.bits(0,18); oversized.bits(1,3);
    oversized.bit(false); oversized.bit(false); oversized.bits(524285,26); oversized.bit(false);
    require(!channel.receive(packet(1,0,0,oversized.data(),static_cast<unsigned>(oversized.position()),true)).valid, "oversized fragment buffer accepted");
    require(channel.incoming_reliable_state() == 0, "rejected reliable transfer toggled acknowledgment");
    // Valid reliable data followed by a malformed unreliable frame must not be
    // acknowledged: the next retransmission has to retain and deliver the data.
    channel.reset();
    const auto frame = hc::encode_message(hc::Message{8,hc::Bytes{7,8},true});
    hc::BitWriter reliable;
    reliable.bits(0,3); reliable.bit(true); reliable.bit(false); reliable.bit(false);
    reliable.bits(static_cast<std::uint32_t>(frame.size()),20); reliable.bytes(frame); reliable.bit(false);
    const auto good_bits = reliable.position();
    const auto good_body = reliable.data();
    reliable.bits(0x80,8);
    require(!channel.receive(packet(1,0,0,reliable.data(),static_cast<unsigned>(reliable.position()),true)).valid, "malformed unreliable tail accepted");
    require(channel.incoming_reliable_state() == 0, "malformed tail acknowledged reliable data");
    auto retried = channel.receive(packet(2,0,0,good_body,static_cast<unsigned>(good_bits),true));
    require(retried.valid && retried.messages.size() == 1 && retried.messages[0].bytes == hc::Bytes({7,8}), "reliable data retained after malformed tail");
    // Outer packet LZSS decompression occurs before netchannel header parsing.
    hc::Netchannel sender(config), receiver(config);
    const auto raw = sender.send().front();
    hc::Bytes compressed{253,255,255,255};
    auto encoded = hc::lzss_compress(raw); compressed.insert(compressed.end(),encoded.begin(),encoded.end());
    require(receiver.receive(compressed).valid, "compressed netchannel packet");
}
hc::Bytes fixture_bytes(const std::string& hex) {
    require(hex.size() % 2 == 0, "fixture hex has odd length");
    const auto nibble = [](char value) -> unsigned {
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'a' && value <= 'f') return value - 'a' + 10;
        if (value >= 'A' && value <= 'F') return value - 'A' + 10;
        throw std::runtime_error("fixture hex contains an invalid digit");
    };
    hc::Bytes result;
    for (std::size_t i = 0; i < hex.size(); i += 2) result.push_back(static_cast<std::uint8_t>(nibble(hex[i]) * 16 + nibble(hex[i + 1])));
    return result;
}
hc::UserCmd expected_command(const nlohmann::json& fixture) {
    hc::UserCmd command;
    command.command_number = fixture.at("command_number").get<std::int32_t>();
    command.tick_count = fixture.at("tick_count").get<std::int32_t>();
    command.viewangles = fixture.at("viewangles").get<std::array<float, 3>>();
    command.aimdirection = fixture.at("aimdirection").get<std::array<float, 3>>();
    command.forwardmove = fixture.at("forwardmove").get<float>();
    command.sidemove = fixture.at("sidemove").get<float>();
    command.upmove = fixture.at("upmove").get<float>();
    command.buttons = fixture.at("buttons").get<std::uint32_t>();
    command.impulse = fixture.at("impulse").get<std::uint8_t>();
    command.weaponselect = fixture.at("weaponselect").get<std::uint16_t>();
    command.weaponsubtype = fixture.at("weaponsubtype").get<std::uint8_t>();
    command.mousedx = fixture.at("mousedx").get<std::int16_t>();
    command.mousedy = fixture.at("mousedy").get<std::int16_t>();
    command.headangles = fixture.at("headangles").get<std::array<float, 3>>();
    command.headoffset = fixture.at("headoffset").get<std::uint32_t>();
    return command;
}
void captured_user_commands() {
    // CTest normally runs inside build/, while standalone execution commonly
    // starts at the repository root. Locate the committed fixture in an ancestor.
    auto root = std::filesystem::current_path();
    std::filesystem::path path;
    for (unsigned depth = 0; depth < 5; ++depth) {
        const auto candidate = root / "tests" / "fixtures" / "legacy_13881_usercmd.json";
        if (std::filesystem::is_regular_file(candidate)) { path = candidate; break; }
        if (root.parent_path() == root) break;
        root = root.parent_path();
    }
    require(!path.empty(), "committed sanitized user-command fixtures are missing");
    std::ifstream input(path);
    nlohmann::json document;
    input >> document;
    require(document.at("host_version") == 13881 && document.at("format_version") == 1, "captured fixture profile mismatch");
    require(document.at("fixtures").size() >= 2, "captured fixtures do not cover multiple stock moves");
    for (const auto& fixture : document.at("fixtures")) {
        require(fixture.at("message_type") == 9, "fixture contains a non-Move message");
        const auto payload = fixture_bytes(fixture.at("protobuf_hex").get<std::string>());
        const hc::Proto move(payload);
        for (const auto& field : move.all_fields())
            require(field.number >= 1 && field.number <= 3 && (field.number == 3 ? field.wire_type == 2 : field.wire_type == 0),
                    "sanitized fixture contains a field outside the installed CLC_Move schema");
        const unsigned backups = move.get_u32(1), fresh = move.get_u32(2);
        require(backups <= 7 && fresh >= 1 && fresh <= 15 && backups == fixture.at("backup_commands") && fresh == fixture.at("new_commands"),
                "captured backup/new command framing changed");
        require(fixture.at("commands").size() == backups + fresh, "captured fixture command count mismatch");
        const auto data = move.get_bytes(3);
        hc::BitReader reader(data);
        hc::BitWriter encoded;
        hc::UserCmd previous;
        for (const auto& expected : fixture.at("commands")) {
            const auto command = hc::read_usercmd_delta(reader, previous);
            require(command == expected_command(expected), "stock user-command fixture semantic decode changed");
            hc::write_usercmd_delta(encoded, command, previous);
            previous = command;
        }
        require(reader.position() == fixture.at("encoded_bits") && reader.remaining() == fixture.at("padding_bits") && reader.remaining() <= 7,
                "stock user-command fixture leaves undecoded non-padding bits");
        require(reader.position() == encoded.position(), "stock user-command reencoding changed bit count");
        for (std::size_t bit = 0; bit < encoded.position(); ++bit)
            require(((data[bit / 8] >> (bit % 8)) & 1) == ((encoded.data()[bit / 8] >> (bit % 8)) & 1),
                    "stock user-command reencoding changed captured wire bits");
        rejects([&] {
            const hc::Bytes truncated(data.begin(), data.end() - 1);
            hc::BitReader malformed(truncated);
            hc::UserCmd command;
            for (unsigned i = 0; i < backups + fresh; ++i) command = hc::read_usercmd_delta(malformed, command);
        }, "truncated captured command data accepted");
        rejects([&] {
            hc::BitReader malformed(data);
            hc::UserCmd command;
            for (unsigned i = 0; i <= backups + fresh; ++i) command = hc::read_usercmd_delta(malformed, command);
        }, "extra command claimed beyond captured data accepted");
    }
}
}
int main(int argc, char** argv) {
    try {
        if (argc == 3 && std::string(argv[1]) == "--capture") {
            std::ifstream input(argv[2]);
            if (!input) throw std::runtime_error("cannot open capture");
            hc::ChannelConfig config; config.passive = true;
            hc::Netchannel c2s(config), s2c(config);
            std::string line; std::size_t row = 0, valid = 0, errors = 0;
            while (std::getline(input,line)) {
                ++row;
                const auto record = nlohmann::json::parse(line);
                const auto hex = record.at("hex").get<std::string>();
                hc::Bytes data;
                for (std::size_t i = 0; i < hex.size(); i += 2) data.push_back(static_cast<std::uint8_t>(std::stoul(hex.substr(i,2),nullptr,16)));
                const auto direction = record.at("direction").get<std::string>();
                auto& channel = direction == "client_to_server" ? c2s : s2c;
                const auto result = channel.receive(data);
                if (!result.valid && !result.pending && result.error != "stale_packet") {
                    ++errors;
                    if (errors <= 5) std::cout << "row=" << row << " direction=" << direction << " error=" << result.error << '\n';
                } else if (result.valid) ++valid;
            }
            std::cout << "rows=" << row << " valid=" << valid << " errors=" << errors << '\n';
            return errors ? 1 : 0;
        }
        bitstreams(); encryption(); compression(); framing(); transport(); malformed_transfer(); captured_user_commands();
        std::cout << "wire tests passed: bitstreams, certified ICE-2, CRC, LZSS, framing, reliable loss recovery, UDP splitting, captured stock user commands, malformed input\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "wire test failure: " << error.what() << '\n';
        return 1;
    }
}
