#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace hc {
using Bytes = std::vector<std::uint8_t>;
class WireError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Source bitstreams store the least significant bit first, including unaligned bytes.
class BitReader {
public:
    explicit BitReader(std::span<const std::uint8_t> data,
                       std::size_t bit_count = std::numeric_limits<std::size_t>::max());
    BitReader(Bytes&&, std::size_t = std::numeric_limits<std::size_t>::max()) = delete;
    std::uint32_t bits(unsigned count);
    std::int32_t signed_bits(unsigned count);
    bool bit();
    std::uint32_t varuint32();
    std::uint64_t varuint64();
    std::uint32_t ubitvar();
    float float32();
    std::string string(std::size_t max_bytes = 4096);
    Bytes bytes(std::size_t count);
    Bytes bit_bytes(std::size_t count);
    void skip(std::size_t count);
    void seek(std::size_t bit_position);
    std::size_t position() const { return position_; }
    std::size_t remaining() const { return bit_count_ - position_; }
    bool empty() const { return remaining() == 0; }
private:
    std::span<const std::uint8_t> data_;
    std::size_t bit_count_;
    std::size_t position_ = 0;
};

class BitWriter {
public:
    explicit BitWriter(std::size_t max_bytes = 524288) : max_bytes_(max_bytes) {}
    void bits(std::uint32_t value, unsigned count);
    void signed_bits(std::int32_t value, unsigned count);
    void bit(bool value);
    void varuint32(std::uint32_t value);
    void varuint64(std::uint64_t value);
    void ubitvar(std::uint32_t value);
    void float32(float value);
    void string(std::string_view value);
    void bytes(std::span<const std::uint8_t> value);
    void bit_bytes(std::span<const std::uint8_t> value, std::size_t bit_count);
    std::size_t position() const { return position_; }
    const Bytes& data() const { return data_; }
    Bytes take();
private:
    void reserve_bits(std::size_t count);
    Bytes data_;
    std::size_t max_bytes_;
    std::size_t position_ = 0;
};

std::uint32_t crc32(std::span<const std::uint8_t> bytes);
std::uint16_t short_checksum(std::span<const std::uint8_t> bytes);
Bytes lzss_decompress(std::span<const std::uint8_t> bytes, std::size_t limit = 524284);
Bytes lzss_compress(std::span<const std::uint8_t> bytes);
std::array<std::uint8_t, 16> default_ice_key(std::uint32_t host_version);

// ICE level 2: 16-byte key, 32 rounds, 8-byte blocks. Based on Matthew Kwan's
// public domain algorithm (1996): https://www.darkside.com.au/ice/ .
class IceCipher {
public:
    explicit IceCipher(const std::array<std::uint8_t, 16>& key);
    Bytes encrypt(std::span<const std::uint8_t> bytes) const;
    Bytes decrypt(std::span<const std::uint8_t> bytes) const;
private:
    std::array<std::array<std::uint32_t, 3>, 32> schedule_{};
    void build_schedule(std::array<std::uint16_t, 4>& words, unsigned start, unsigned rotation);
};
Bytes encrypt_envelope(std::span<const std::uint8_t> bytes,
                       const std::array<std::uint8_t, 16>& key);
Bytes decrypt_envelope(std::span<const std::uint8_t> bytes,
                       const std::array<std::uint8_t, 16>& key,
                       std::size_t limit = 524400);
} // namespace hc
