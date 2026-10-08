#pragma once

#include "hc/wire.hpp"
#include <array>
#include <chrono>
#include <deque>
#include <map>
#include <optional>

namespace hc {
struct Message {
    std::uint32_t type = 0;
    Bytes bytes;
    bool reliable = false;
};
Bytes encode_message(const Message& message);
std::vector<Message> decode_messages(BitReader& reader, bool reliable = false);

struct ChannelConfig {
    std::uint32_t host_version = 13881;
    bool encryption = true;
    bool passive = false; // Offline directional capture decoding; no outbound acknowledgment state.
    std::array<std::uint8_t, 16> encryption_key = default_ice_key(13881);
    std::size_t max_routable = 1200;
    std::size_t max_normal_bytes = 524284;
    std::size_t max_file_bytes = (64 * 1024 * 1024) - 1;
    unsigned reliable_fragments_per_packet = 4;
};
struct FileTransfer {
    std::uint32_t id = 0;
    std::string filename;
    bool replay = false;
    Bytes bytes;
};
struct PacketResult {
    bool valid = false;
    bool pending = false;
    bool connectionless = false;
    std::uint32_t sequence = 0;
    std::uint32_t ack = 0;
    std::uint32_t dropped = 0;
    std::vector<Message> messages;
    std::vector<FileTransfer> files;
    Bytes connectionless_payload;
    std::string error;
};

// This class owns protocol state only. UDP I/O, destination policy, timeout,
// bandwidth/tick pacing, and authentication belong to the session layer.
class Netchannel {
public:
    explicit Netchannel(ChannelConfig config = {});
    void reset();
    void queue(Message message, bool reliable = true);
    std::vector<Bytes> send(std::span<const Message> unreliable = {});
    PacketResult receive(std::span<const std::uint8_t> datagram);
    std::uint32_t incoming_sequence() const { return incoming_sequence_; }
    std::uint32_t outgoing_sequence() const { return outgoing_sequence_; }
    std::uint32_t acknowledged_sequence() const { return acknowledged_sequence_; }
    std::uint8_t incoming_reliable_state() const { return incoming_reliable_; }
    std::uint8_t outgoing_reliable_state() const { return outgoing_reliable_; }
    bool pending_reliable() const { return !outgoing_transfers_.empty(); }
    void set_encryption_key(const std::array<std::uint8_t, 16>& key) { config_.encryption_key = key; }
    void set_encryption(bool enabled) { config_.encryption = enabled; }
private:
    struct OutgoingTransfer {
        Bytes bytes;
        std::size_t next_fragment = 0;
        std::size_t acknowledged_fragments = 0;
    };
    struct Subchannel {
        bool used = false;
        bool resend = false;
        std::size_t start = 0;
        unsigned count = 0;
        std::uint32_t sent_sequence = 0;
    };
    struct IncomingTransfer {
        Bytes bytes;
        std::vector<bool> fragments;
        bool compressed = false;
        std::size_t uncompressed_size = 0;
        std::uint32_t id = 0;
        std::string filename;
        bool replay = false;
        bool active = false;
    };
    struct SplitTransfer {
        std::uint8_t count = 0;
        std::uint16_t chunk_size = 0;
        std::vector<std::optional<Bytes>> chunks;
        std::chrono::steady_clock::time_point updated;
    };
    std::optional<Bytes> assemble_split(std::span<const std::uint8_t> bytes);
    void acknowledge(std::uint32_t sequence_ack, std::uint8_t state);
    void read_transfer(BitReader& reader, unsigned stream, PacketResult& result);
    void write_transfer(BitWriter& writer, unsigned subchannel);
    std::vector<Bytes> split_outgoing(const Bytes& bytes);

    ChannelConfig config_;
    std::uint32_t incoming_sequence_ = 0;
    std::uint32_t outgoing_sequence_ = 1;
    std::uint32_t acknowledged_sequence_ = 0;
    std::uint32_t split_sequence_ = 1;
    std::uint8_t incoming_reliable_ = 0;
    std::uint8_t outgoing_reliable_ = 0;
    std::array<Subchannel, 8> subchannels_{};
    std::array<IncomingTransfer, 2> incoming_transfers_{};
    std::deque<OutgoingTransfer> outgoing_transfers_;
    std::deque<Message> unreliable_queue_;
    std::map<std::uint32_t, SplitTransfer> split_transfers_;
};
} // namespace hc
