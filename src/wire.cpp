#include "hc/wire.hpp"

#include <algorithm>
#include <bit>
#include <cstring>
#include <random>
#include <utility>

namespace hc {
BitReader::BitReader(std::span<const std::uint8_t> data, std::size_t bit_count)
    : data_(data), bit_count_(bit_count == std::numeric_limits<std::size_t>::max() ? data.size() * 8 : bit_count) {
    if (bit_count_ > data.size() * 8) throw WireError("bitstream length exceeds buffer");
}
std::uint32_t BitReader::bits(unsigned count) {
    if (count > 32 || count > remaining()) throw WireError("truncated bitstream");
    std::uint32_t value = 0;
    for (unsigned i = 0; i < count; ++i) {
        value |= std::uint32_t((data_[position_ / 8] >> (position_ % 8)) & 1) << i;
        ++position_;
    }
    return value;
}
std::int32_t BitReader::signed_bits(unsigned count) {
    if (count == 0 || count > 32) throw WireError("invalid signed bit width");
    auto value = bits(count);
    if (count < 32 && (value & (std::uint32_t(1) << (count - 1)))) value |= ~((std::uint32_t(1) << count) - 1);
    return std::bit_cast<std::int32_t>(value);
}
bool BitReader::bit() { return bits(1) != 0; }
std::uint32_t BitReader::varuint32() {
    std::uint32_t value = 0;
    for (unsigned i = 0; i < 5; ++i) {
        const auto byte = bits(8);
        if (i == 4 && byte > 15) throw WireError("varuint32 overflow");
        value |= (byte & 127) << (i * 7);
        if (!(byte & 128)) return value;
    }
    throw WireError("unterminated varuint32");
}
std::uint64_t BitReader::varuint64() {
    std::uint64_t value = 0;
    for (unsigned i = 0; i < 10; ++i) {
        const auto byte = bits(8);
        if (i == 9 && byte > 1) throw WireError("varuint64 overflow");
        value |= std::uint64_t(byte & 127) << (i * 7);
        if (!(byte & 128)) return value;
    }
    throw WireError("unterminated varuint64");
}
std::uint32_t BitReader::ubitvar() {
    const auto first = bits(6);
    switch (first & 48) {
        case 16: return (first & 15) | (bits(4) << 4);
        case 32: return (first & 15) | (bits(8) << 4);
        case 48: return (first & 15) | (bits(28) << 4);
        default: return first;
    }
}
float BitReader::float32() { return std::bit_cast<float>(bits(32)); }
std::string BitReader::string(std::size_t max_bytes) {
    std::string result;
    for (std::size_t i = 0; i < max_bytes; ++i) {
        const auto value = static_cast<char>(bits(8));
        if (!value) return result;
        result.push_back(value);
    }
    throw WireError("unterminated or oversized string");
}
Bytes BitReader::bytes(std::size_t count) {
    if (count > remaining() / 8) throw WireError("truncated byte buffer");
    if ((position_ & 7) == 0) {
        auto begin = data_.begin() + position_ / 8;
        Bytes result(begin, begin + count);
        position_ += count * 8;
        return result;
    }
    Bytes result(count);
    for (auto& value : result) value = static_cast<std::uint8_t>(bits(8));
    return result;
}
Bytes BitReader::bit_bytes(std::size_t count) {
    if (count > remaining()) throw WireError("truncated bit buffer");
    auto result = bytes(count / 8);
    if (count & 7) result.push_back(static_cast<std::uint8_t>(bits(static_cast<unsigned>(count & 7))));
    return result;
}
void BitReader::skip(std::size_t count) {
    if (count > remaining()) throw WireError("skip exceeds bitstream");
    position_ += count;
}
void BitReader::seek(std::size_t bit_position) {
    if (bit_position > bit_count_) throw WireError("seek exceeds bitstream");
    position_ = bit_position;
}

void BitWriter::reserve_bits(std::size_t count) {
    if (count > max_bytes_ * 8 || position_ > max_bytes_ * 8 - count) throw WireError("bit writer capacity exceeded");
    data_.resize((position_ + count + 7) / 8, 0);
}
void BitWriter::bits(std::uint32_t value, unsigned count) {
    if (count > 32) throw WireError("invalid bit width");
    reserve_bits(count);
    for (unsigned i = 0; i < count; ++i) {
        if ((value >> i) & 1) data_[position_ / 8] |= std::uint8_t(1u << (position_ % 8));
        ++position_;
    }
}
void BitWriter::signed_bits(std::int32_t value, unsigned count) {
    if (count == 0) throw WireError("invalid signed bit width");
    bits(std::bit_cast<std::uint32_t>(value), count);
}
void BitWriter::bit(bool value) { bits(value ? 1u : 0u, 1); }
void BitWriter::varuint32(std::uint32_t value) { varuint64(value); }
void BitWriter::varuint64(std::uint64_t value) {
    do {
        auto byte = static_cast<std::uint8_t>(value & 127);
        value >>= 7;
        bits(byte | (value ? 128u : 0u), 8);
    } while (value);
}
void BitWriter::ubitvar(std::uint32_t value) {
    if (value < 16) bits(value, 6);
    else if (value < 256) { bits((value & 15) | 16, 6); bits(value >> 4, 4); }
    else if (value < 4096) { bits((value & 15) | 32, 6); bits(value >> 4, 8); }
    else { bits((value & 15) | 48, 6); bits(value >> 4, 28); }
}
void BitWriter::float32(float value) { bits(std::bit_cast<std::uint32_t>(value), 32); }
void BitWriter::string(std::string_view value) {
    if (value.find('\0') != std::string_view::npos) throw WireError("embedded NUL in wire string");
    for (auto character : value) bits(static_cast<std::uint8_t>(character), 8);
    bits(0, 8);
}
void BitWriter::bytes(std::span<const std::uint8_t> value) {
    if ((position_ & 7) == 0) {
        const auto offset = position_ / 8;
        reserve_bits(value.size() * 8);
        std::copy(value.begin(), value.end(), data_.begin() + offset);
        position_ += value.size() * 8;
    } else for (auto byte : value) bits(byte, 8);
}
void BitWriter::bit_bytes(std::span<const std::uint8_t> value, std::size_t bit_count) {
    if (bit_count > value.size() * 8) throw WireError("bit buffer length exceeds buffer");
    bytes(value.first(bit_count / 8));
    if (bit_count & 7) bits(value[bit_count / 8], static_cast<unsigned>(bit_count & 7));
}
Bytes BitWriter::take() { position_ = 0; return std::exchange(data_, {}); }

std::uint32_t crc32(std::span<const std::uint8_t> bytes) {
    static const auto table = [] {
        std::array<std::uint32_t, 256> result{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            auto value = i;
            for (unsigned j = 0; j < 8; ++j) value = (value >> 1) ^ ((value & 1) ? 0xedb88320u : 0u);
            result[i] = value;
        }
        return result;
    }();
    std::uint32_t result = 0xffffffffu;
    for (auto byte : bytes) result = (result >> 8) ^ table[(result ^ byte) & 255];
    return result ^ 0xffffffffu;
}
std::uint16_t short_checksum(std::span<const std::uint8_t> bytes) {
    const auto value = crc32(bytes);
    return static_cast<std::uint16_t>(value ^ (value >> 16));
}
namespace {
std::uint32_t little32(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 4) throw WireError("truncated 32-bit word");
    return std::uint32_t(bytes[0]) | (std::uint32_t(bytes[1]) << 8) | (std::uint32_t(bytes[2]) << 16) | (std::uint32_t(bytes[3]) << 24);
}
std::uint32_t big32(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 4) throw WireError("truncated 32-bit word");
    return (std::uint32_t(bytes[0]) << 24) | (std::uint32_t(bytes[1]) << 16) | (std::uint32_t(bytes[2]) << 8) | std::uint32_t(bytes[3]);
}
void put_big32(std::span<std::uint8_t> bytes, std::uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) bytes[i] = static_cast<std::uint8_t>(value >> ((3 - i) * 8));
}
}
Bytes lzss_decompress(std::span<const std::uint8_t> bytes, std::size_t limit) {
    if (bytes.size() < 8 || bytes[0] != 'L' || bytes[1] != 'Z' || bytes[2] != 'S' || bytes[3] != 'S') throw WireError("invalid LZSS header");
    const auto expected = little32(bytes.subspan(4, 4));
    if (expected > limit) throw WireError("LZSS output exceeds limit");
    Bytes result;
    result.reserve(expected);
    std::size_t offset = 8;
    while (offset < bytes.size()) {
        const auto command = bytes[offset++];
        for (unsigned token = 0; token < 8; ++token) {
            if (command & (1u << token)) {
                if (bytes.size() - offset < 2) throw WireError("truncated LZSS reference");
                const std::size_t distance = (std::size_t(bytes[offset]) << 4) | (bytes[offset + 1] >> 4);
                const std::size_t count = (bytes[offset + 1] & 15) + 1;
                offset += 2;
                if (count == 1) {
                    if (result.size() != expected) throw WireError("LZSS output size mismatch");
                    return result;
                }
                if (distance >= result.size()) throw WireError("LZSS reference precedes output");
                if (count > expected - result.size()) throw WireError("LZSS output overruns advertised size");
                const auto begin = result.size() - distance - 1;
                for (std::size_t i = 0; i < count; ++i) result.push_back(result[begin + i]);
            } else {
                if (offset >= bytes.size()) throw WireError("truncated LZSS literal");
                if (result.size() >= expected) throw WireError("LZSS output overruns advertised size");
                result.push_back(bytes[offset++]);
            }
        }
    }
    throw WireError("missing LZSS terminator");
}
Bytes lzss_compress(std::span<const std::uint8_t> bytes) {
    if (bytes.size() > std::numeric_limits<std::uint32_t>::max()) throw WireError("LZSS input too large");
    BitWriter header(bytes.size() + 16);
    header.bytes(std::array<std::uint8_t, 4>{'L', 'Z', 'S', 'S'});
    header.bits(static_cast<std::uint32_t>(bytes.size()), 32);
    auto output = header.take();
    std::array<std::int64_t, 65536> heads;
    heads.fill(-1);
    std::vector<std::int64_t> previous(bytes.size(), -1);
    std::size_t command_offset = 0;
    unsigned token = 8;
    auto start_token = [&] {
        if (token == 8) { command_offset = output.size(); output.push_back(0); token = 0; }
    };
    auto remember = [&](std::size_t position) {
        if (position + 1 < bytes.size()) {
            const unsigned hash = (unsigned(bytes[position]) << 8) | bytes[position + 1];
            previous[position] = heads[hash];
            heads[hash] = static_cast<std::int64_t>(position);
        }
    };
    std::size_t position = 0;
    while (position < bytes.size()) {
        start_token();
        std::size_t best_count = 0, best_distance = 0;
        if (position + 2 < bytes.size()) {
            const unsigned hash = (unsigned(bytes[position]) << 8) | bytes[position + 1];
            auto candidate = heads[hash];
            const auto maximum = std::min<std::size_t>(16, bytes.size() - position);
            for (unsigned attempts = 0; candidate >= 0 && attempts < 128; ++attempts) {
                const auto source = static_cast<std::size_t>(candidate);
                if (position - source > 4096) break;
                std::size_t count = 0;
                while (count < maximum && bytes[source + count] == bytes[position + count]) ++count;
                if (count > best_count) { best_count = count; best_distance = position - source - 1; }
                if (count == maximum) break;
                candidate = previous[source];
            }
        }
        const auto consumed = best_count >= 3 ? best_count : std::size_t(1);
        if (best_count >= 3) {
            output[command_offset] |= static_cast<std::uint8_t>(1u << token);
            output.push_back(static_cast<std::uint8_t>(best_distance >> 4));
            output.push_back(static_cast<std::uint8_t>((best_distance << 4) | (best_count - 1)));
        } else output.push_back(bytes[position]);
        for (std::size_t i = 0; i < consumed; ++i) remember(position + i);
        position += consumed;
        ++token;
    }
    start_token();
    output[command_offset] |= static_cast<std::uint8_t>(1u << token);
    output.push_back(0);
    output.push_back(0);
    return output;
}

std::array<std::uint8_t, 16> default_ice_key(std::uint32_t host_version) {
    std::array<std::uint8_t, 16> key{'C', 'S', 'G', 'O'};
    constexpr std::array<unsigned, 12> shifts{0, 8, 16, 24, 2, 10, 18, 26, 4, 12, 20, 28};
    for (unsigned i = 0; i < shifts.size(); ++i) key[i + 4] = static_cast<std::uint8_t>(host_version >> shifts[i]);
    return key;
}
namespace {
constexpr std::array<unsigned, 16> key_rotation{0, 1, 2, 3, 2, 1, 3, 0, 1, 3, 2, 0, 3, 1, 0, 2};
std::uint32_t gf_multiply(std::uint32_t a, std::uint32_t b, std::uint32_t modulus) {
    std::uint32_t result = 0;
    while (b) {
        if (b & 1) result ^= a;
        a <<= 1;
        b >>= 1;
        if (a >= 256) a ^= modulus;
    }
    return result;
}
std::uint32_t gf_power7(std::uint32_t value, std::uint32_t modulus) {
    auto result = gf_multiply(value, value, modulus);
    result = gf_multiply(value, result, modulus);
    result = gf_multiply(result, result, modulus);
    return gf_multiply(value, result, modulus);
}
std::uint32_t permute(std::uint32_t value) {
    constexpr std::array<std::uint32_t, 32> box{
        0x00000001, 0x00000080, 0x00000400, 0x00002000, 0x00080000, 0x00200000, 0x01000000, 0x40000000,
        0x00000008, 0x00000020, 0x00000100, 0x00004000, 0x00010000, 0x00800000, 0x04000000, 0x20000000,
        0x00000004, 0x00000010, 0x00000200, 0x00008000, 0x00020000, 0x00400000, 0x08000000, 0x10000000,
        0x00000002, 0x00000040, 0x00000800, 0x00001000, 0x00040000, 0x00100000, 0x02000000, 0x80000000};
    std::uint32_t result = 0;
    for (unsigned i = 0; i < 32; ++i) if ((value >> i) & 1) result |= box[i];
    return result;
}
const auto& ice_boxes() {
    static const auto boxes = [] {
        constexpr unsigned modulus[4][4]{{333, 313, 505, 369}, {379, 375, 319, 391}, {361, 445, 451, 397}, {397, 425, 395, 505}};
        constexpr unsigned salt[4][4]{{0x83, 0x85, 0x9b, 0xcd}, {0xcc, 0xa7, 0xad, 0x41}, {0x4b, 0x2e, 0xd4, 0x33}, {0xea, 0xcb, 0x2e, 0x04}};
        std::array<std::array<std::uint32_t, 1024>, 4> result{};
        for (unsigned i = 0; i < 1024; ++i) {
            const unsigned column = (i >> 1) & 255;
            const unsigned row = (i & 1) | ((i & 512) >> 8);
            for (unsigned box = 0; box < 4; ++box) result[box][i] = permute(gf_power7(column ^ salt[box][row], modulus[box][row]) << ((3 - box) * 8));
        }
        return result;
    }();
    return boxes;
}
std::uint32_t ice_round(std::uint32_t value, const std::array<std::uint32_t, 3>& key) {
    const std::uint32_t left = ((value >> 16) & 1023) | (((value >> 14) | (value << 18)) & 0xffc00);
    const std::uint32_t right = (value & 1023) | ((value << 2) & 0xffc00);
    const auto mixed = key[2] & (left ^ right);
    const auto a = (mixed ^ left) ^ key[0];
    const auto b = (mixed ^ right) ^ key[1];
    const auto& box = ice_boxes();
    return box[0][a >> 10] | box[1][a & 1023] | box[2][b >> 10] | box[3][b & 1023];
}
}
IceCipher::IceCipher(const std::array<std::uint8_t, 16>& key) {
    for (unsigned half = 0; half < 2; ++half) {
        std::array<std::uint16_t, 4> words{};
        for (unsigned i = 0; i < 4; ++i) words[3 - i] = static_cast<std::uint16_t>((std::uint32_t(key[half * 8 + i * 2]) << 8) | key[half * 8 + i * 2 + 1]);
        build_schedule(words, half * 8, 0);
        build_schedule(words, 24 - half * 8, 8);
    }
}
void IceCipher::build_schedule(std::array<std::uint16_t, 4>& words, unsigned start, unsigned rotation) {
    for (unsigned round = 0; round < 8; ++round) {
        auto& subkey = schedule_[start + round];
        for (unsigned step = 0; step < 15; ++step) {
            for (unsigned word = 0; word < 4; ++word) {
                auto& value = words[(key_rotation[rotation + round] + word) & 3];
                const auto bit = value & 1;
                subkey[step % 3] = (subkey[step % 3] << 1) | bit;
                value = static_cast<std::uint16_t>((value >> 1) | ((bit ^ 1) << 15));
            }
        }
    }
}
Bytes IceCipher::encrypt(std::span<const std::uint8_t> bytes) const {
    if (bytes.size() % 8) throw WireError("ICE input is not block aligned");
    Bytes result(bytes.size());
    for (std::size_t offset = 0; offset < bytes.size(); offset += 8) {
        auto left = big32(bytes.subspan(offset, 4));
        auto right = big32(bytes.subspan(offset + 4, 4));
        for (unsigned round = 0; round < 32; round += 2) {
            left ^= ice_round(right, schedule_[round]);
            right ^= ice_round(left, schedule_[round + 1]);
        }
        put_big32(std::span(result).subspan(offset, 4), right);
        put_big32(std::span(result).subspan(offset + 4, 4), left);
    }
    return result;
}
Bytes IceCipher::decrypt(std::span<const std::uint8_t> bytes) const {
    if (bytes.size() % 8) throw WireError("ICE input is not block aligned");
    Bytes result(bytes.size());
    for (std::size_t offset = 0; offset < bytes.size(); offset += 8) {
        auto left = big32(bytes.subspan(offset, 4));
        auto right = big32(bytes.subspan(offset + 4, 4));
        for (int round = 31; round > 0; round -= 2) {
            left ^= ice_round(right, schedule_[round]);
            right ^= ice_round(left, schedule_[round - 1]);
        }
        put_big32(std::span(result).subspan(offset, 4), right);
        put_big32(std::span(result).subspan(offset + 4, 4), left);
    }
    return result;
}
Bytes encrypt_envelope(std::span<const std::uint8_t> bytes, const std::array<std::uint8_t, 16>& key) {
    if (bytes.size() > 524400) throw WireError("encrypted packet exceeds limit");
    std::random_device random;
    std::size_t padding = 16 + random() % 57;
    padding += 8 - ((1 + padding + 4 + bytes.size()) % 8);
    Bytes envelope(1 + padding + 4 + bytes.size());
    envelope[0] = static_cast<std::uint8_t>(padding);
    for (std::size_t i = 0; i < padding; ++i) envelope[i + 1] = static_cast<std::uint8_t>(16 + random() % 235);
    put_big32(std::span(envelope).subspan(1 + padding, 4), static_cast<std::uint32_t>(bytes.size()));
    std::copy(bytes.begin(), bytes.end(), envelope.begin() + 1 + padding + 4);
    return IceCipher(key).encrypt(envelope);
}
Bytes decrypt_envelope(std::span<const std::uint8_t> bytes, const std::array<std::uint8_t, 16>& key, std::size_t limit) {
    if (bytes.empty() || bytes.size() > limit + 85) throw WireError("invalid encrypted packet length");
    const auto envelope = IceCipher(key).decrypt(bytes);
    const std::size_t padding = envelope[0];
    const auto offset = 1 + padding + 4;
    if (!padding || offset >= envelope.size()) throw WireError("invalid encrypted packet padding");
    const auto size = big32(std::span(envelope).subspan(1 + padding, 4));
    if (size > limit || size != envelope.size() - offset) throw WireError("invalid encrypted packet size");
    return Bytes(envelope.begin() + offset, envelope.end());
}
} // namespace hc
