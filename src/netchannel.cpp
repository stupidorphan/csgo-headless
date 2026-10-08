#include "hc/netchannel.hpp"

#include <algorithm>
#include <bit>
#include <limits>

namespace hc {
namespace {
constexpr std::uint32_t split_magic = 0xfffffffeu;
constexpr std::uint32_t compressed_magic = 0xfffffffdu;
constexpr std::uint32_t connectionless_magic = 0xffffffffu;
constexpr std::size_t fragment_size = 256;
constexpr unsigned normal_size_bits = 19;
constexpr unsigned file_size_bits = 26;
std::uint32_t word(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 4) throw WireError("truncated packet marker");
    return std::uint32_t(bytes[0]) | (std::uint32_t(bytes[1]) << 8) | (std::uint32_t(bytes[2]) << 16) | (std::uint32_t(bytes[3]) << 24);
}
std::size_t fragment_count(std::size_t bytes) { return (bytes + fragment_size - 1) / fragment_size; }
bool newer(std::uint32_t a, std::uint32_t b) { return std::bit_cast<std::int32_t>(a - b) > 0; }
void append_message(BitWriter& writer, const Message& message) {
    if (message.bytes.size() > 524284) throw WireError("protobuf message exceeds packet limit");
    writer.varuint32(message.type);
    writer.varuint32(static_cast<std::uint32_t>(message.bytes.size()));
    writer.bytes(message.bytes);
}
}

Bytes encode_message(const Message& message) {
    BitWriter writer(524300);
    append_message(writer, message);
    return writer.take();
}
std::vector<Message> decode_messages(BitReader& reader, bool reliable) {
    std::vector<Message> result;
    while (!reader.empty()) {
        const auto type = reader.varuint32();
        const auto size = reader.varuint32();
        if (size > 524284 || size > reader.remaining() / 8) throw WireError("invalid protobuf frame length");
        auto data = reader.bytes(size);
        if (type != 0) result.push_back(Message{type, std::move(data), reliable});
        else if (size != 0) throw WireError("NOP frame has a payload");
        if (result.size() > 32768) throw WireError("too many protobuf frames");
    }
    return result;
}

Netchannel::Netchannel(ChannelConfig config) : config_(config) {
    if (config_.max_routable < 576 || config_.max_routable > 1200) throw WireError("routable packet size outside Source range [576,1200]");
    if (!config_.max_normal_bytes || config_.max_normal_bytes > 524284) throw WireError("invalid normal stream limit");
    if (!config_.max_file_bytes || config_.max_file_bytes >= (std::size_t(1) << file_size_bits)) throw WireError("invalid file stream limit");
    if (!config_.reliable_fragments_per_packet || config_.reliable_fragments_per_packet > 7) throw WireError("invalid fragments per packet");
    if (config_.encryption_key == default_ice_key(13881)) config_.encryption_key = default_ice_key(config_.host_version);
}
void Netchannel::reset() {
    incoming_sequence_ = acknowledged_sequence_ = 0;
    outgoing_sequence_ = split_sequence_ = 1;
    incoming_reliable_ = outgoing_reliable_ = 0;
    subchannels_ = {};
    incoming_transfers_ = {};
    outgoing_transfers_.clear();
    unreliable_queue_.clear();
    split_transfers_.clear();
}
void Netchannel::queue(Message message, bool reliable) {
    if (!reliable) {
        if (unreliable_queue_.size() >= 4096) throw WireError("unreliable message queue is full");
        unreliable_queue_.push_back(std::move(message));
        return;
    }
    auto frame = encode_message(message);
    if (frame.size() > config_.max_normal_bytes) throw WireError("reliable frame exceeds stream limit");
    // New frames may be combined with an unsent tail, preserving message order.
    if (!outgoing_transfers_.empty() && outgoing_transfers_.back().next_fragment == 0 &&
        outgoing_transfers_.back().bytes.size() + frame.size() <= config_.max_normal_bytes) {
        auto& bytes = outgoing_transfers_.back().bytes;
        bytes.insert(bytes.end(), frame.begin(), frame.end());
    } else {
        if (outgoing_transfers_.size() >= 128) throw WireError("reliable message queue is full");
        outgoing_transfers_.push_back(OutgoingTransfer{std::move(frame)});
    }
}
void Netchannel::acknowledge(std::uint32_t sequence_ack, std::uint8_t state) {
    if (newer(sequence_ack, outgoing_sequence_ - 1)) throw WireError("peer acknowledged an unsent sequence");
    for (unsigned i = 0; i < subchannels_.size(); ++i) {
        auto& channel = subchannels_[i];
        if (!channel.used) continue;
        if (newer(channel.sent_sequence, sequence_ack)) continue;
        const auto mask = static_cast<std::uint8_t>(1u << i);
        if ((outgoing_reliable_ & mask) == (state & mask)) {
            if (outgoing_transfers_.empty()) throw WireError("reliable acknowledgment has no pending transfer");
            outgoing_transfers_.front().acknowledged_fragments += channel.count;
            channel = {};
        } else channel.resend = true;
    }
    if (!outgoing_transfers_.empty() && outgoing_transfers_.front().acknowledged_fragments == fragment_count(outgoing_transfers_.front().bytes.size())) {
        outgoing_transfers_.pop_front();
    }
    if (newer(sequence_ack, acknowledged_sequence_)) acknowledged_sequence_ = sequence_ack;
}
void Netchannel::write_transfer(BitWriter& writer, unsigned index) {
    auto& channel = subchannels_[index];
    const auto& transfer = outgoing_transfers_.front();
    const auto total_fragments = fragment_count(transfer.bytes.size());
    const auto offset = channel.start * fragment_size;
    const auto size = std::min<std::size_t>(channel.count * fragment_size, transfer.bytes.size() - offset);
    writer.bits(index, 3);
    writer.bit(true); // normal stream present
    const bool single = channel.start == 0 && channel.count == total_fragments;
    writer.bit(!single);
    if (single) {
        writer.bit(false); // uncompressed
        writer.bits(static_cast<std::uint32_t>(transfer.bytes.size()), normal_size_bits);
    } else {
        writer.bits(static_cast<std::uint32_t>(channel.start), file_size_bits - 8);
        writer.bits(channel.count, 3);
        if (channel.start == 0) {
            writer.bit(false); // normal messages, no filename
            writer.bit(false); // uncompressed
            writer.bits(static_cast<std::uint32_t>(transfer.bytes.size()), file_size_bits);
        }
    }
    writer.bytes(std::span(transfer.bytes).subspan(offset, size));
    writer.bit(false); // file stream absent
    channel.sent_sequence = outgoing_sequence_;
    channel.resend = false;
}
std::vector<Bytes> Netchannel::send(std::span<const Message> unreliable) {
    BitWriter writer(524400);
    writer.bits(outgoing_sequence_, 32);
    writer.bits(incoming_sequence_, 32);
    writer.bits(0, 8); // flags, assigned after padding
    writer.bits(0, 16); // checksum, assigned after padding
    writer.bits(incoming_reliable_, 8);
    std::uint8_t flags = 0;
    std::optional<unsigned> selected;
    for (unsigned i = 0; i < subchannels_.size(); ++i) {
        if (subchannels_[i].used && subchannels_[i].resend) { selected = i; break; }
    }
    if (!selected && !outgoing_transfers_.empty()) {
        auto& transfer = outgoing_transfers_.front();
        const auto fragments = fragment_count(transfer.bytes.size());
        if (transfer.next_fragment < fragments) {
            for (unsigned i = 0; i < subchannels_.size(); ++i) {
                if (subchannels_[i].used) continue;
                const auto count = static_cast<unsigned>(std::min<std::size_t>(config_.reliable_fragments_per_packet, fragments - transfer.next_fragment));
                subchannels_[i] = Subchannel{true, true, transfer.next_fragment, count, 0};
                transfer.next_fragment += count;
                outgoing_reliable_ ^= static_cast<std::uint8_t>(1u << i);
                selected = i;
                break;
            }
        }
    }
    if (selected) { write_transfer(writer, *selected); flags |= 1; }
    while (!unreliable_queue_.empty()) {
        append_message(writer, unreliable_queue_.front());
        unreliable_queue_.pop_front();
    }
    for (const auto& message : unreliable) append_message(writer, message);
    while ((writer.position() + 7) / 8 < 16) append_message(writer, Message{});
    const auto padding = static_cast<unsigned>((8 - (writer.position() & 7)) & 7);
    if (padding) { flags |= static_cast<std::uint8_t>(padding << 5); writer.bits((1u << padding) - 1, padding); }
    auto packet = writer.take();
    packet[8] = flags;
    const auto checksum = short_checksum(std::span(packet).subspan(11));
    packet[9] = static_cast<std::uint8_t>(checksum);
    packet[10] = static_cast<std::uint8_t>(checksum >> 8);
    auto wire = config_.encryption ? encrypt_envelope(packet, config_.encryption_key) : std::move(packet);
    auto datagrams = split_outgoing(wire);
    ++outgoing_sequence_;
    return datagrams;
}
std::vector<Bytes> Netchannel::split_outgoing(const Bytes& bytes) {
    if (bytes.size() <= config_.max_routable) return {bytes};
    const auto chunk_size = config_.max_routable - 12;
    const auto count = (bytes.size() + chunk_size - 1) / chunk_size;
    if (count > 255) throw WireError("packet requires more than 255 UDP split parts");
    std::vector<Bytes> result;
    for (std::size_t index = 0; index < count; ++index) {
        const auto offset = index * chunk_size;
        BitWriter writer(config_.max_routable);
        writer.bits(split_magic, 32);
        writer.bits(split_sequence_, 32);
        writer.bits(static_cast<std::uint32_t>((index << 8) | count), 16);
        writer.bits(static_cast<std::uint32_t>(chunk_size), 16);
        writer.bytes(std::span(bytes).subspan(offset, std::min(chunk_size, bytes.size() - offset)));
        result.push_back(writer.take());
    }
    ++split_sequence_;
    return result;
}
std::optional<Bytes> Netchannel::assemble_split(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 12) throw WireError("truncated UDP split header");
    BitReader reader(bytes);
    reader.bits(32);
    const auto sequence = reader.bits(32);
    const auto packet_id = reader.bits(16);
    const auto chunk_size = reader.bits(16);
    const auto index = packet_id >> 8;
    const auto count = packet_id & 255;
    if (!count || index >= count || chunk_size < 564 || chunk_size > 1188) throw WireError("invalid UDP split geometry");
    const auto size = bytes.size() - 12;
    if (size > chunk_size || !size || (index + 1 < count && size != chunk_size)) throw WireError("invalid UDP split part length");
    if ((count - 1) * chunk_size >= config_.max_normal_bytes + 128) throw WireError("UDP split packet exceeds limit");
    const auto now = std::chrono::steady_clock::now();
    for (auto it = split_transfers_.begin(); it != split_transfers_.end();) {
        if (now - it->second.updated > std::chrono::seconds(5)) it = split_transfers_.erase(it);
        else ++it;
    }
    auto found = split_transfers_.find(sequence);
    if (found == split_transfers_.end()) {
        if (split_transfers_.size() >= 8) throw WireError("too many incomplete UDP split packets");
        found = split_transfers_.emplace(sequence, SplitTransfer{static_cast<std::uint8_t>(count), static_cast<std::uint16_t>(chunk_size), std::vector<std::optional<Bytes>>(count), now}).first;
    }
    auto& transfer = found->second;
    if (transfer.count != count || transfer.chunk_size != chunk_size) throw WireError("inconsistent UDP split headers");
    auto part = Bytes(bytes.begin() + 12, bytes.end());
    if (transfer.chunks[index] && *transfer.chunks[index] != part) throw WireError("conflicting duplicate UDP split part");
    transfer.chunks[index] = std::move(part);
    transfer.updated = now;
    if (std::any_of(transfer.chunks.begin(), transfer.chunks.end(), [](const auto& chunk) { return !chunk; })) return std::nullopt;
    Bytes result;
    for (const auto& chunk : transfer.chunks) result.insert(result.end(), chunk->begin(), chunk->end());
    split_transfers_.erase(found);
    if (result.size() > config_.max_normal_bytes + 128) throw WireError("assembled UDP packet exceeds limit");
    return result;
}
void Netchannel::read_transfer(BitReader& reader, unsigned stream, PacketResult& result) {
    auto& transfer = incoming_transfers_[stream];
    const bool single = !reader.bit();
    std::size_t start = 0, count = 0;
    if (!single) {
        start = reader.bits(file_size_bits - 8);
        count = reader.bits(3);
        if (!count) throw WireError("empty reliable fragment group");
    }
    if (start == 0) {
        IncomingTransfer incoming;
        if (!single && reader.bit()) {
            incoming.id = reader.bits(32);
            incoming.filename = reader.string(260);
            incoming.replay = reader.bit();
        }
        incoming.compressed = reader.bit();
        if (incoming.compressed) incoming.uncompressed_size = reader.bits(file_size_bits);
        const auto size = reader.bits(single ? normal_size_bits : file_size_bits);
        const auto limit = incoming.filename.empty() ? config_.max_normal_bytes : config_.max_file_bytes;
        if (!size || size > limit || (incoming.compressed && (!incoming.uncompressed_size || incoming.uncompressed_size > limit))) throw WireError("reliable stream exceeds configured limit");
        incoming.bytes.resize(size);
        incoming.fragments.resize(fragment_count(size), false);
        incoming.active = true;
        transfer = std::move(incoming);
        if (single) count = transfer.fragments.size();
    } else if (!transfer.active) throw WireError("reliable fragment arrived before its header");
    if (start >= transfer.fragments.size() || count > transfer.fragments.size() - start) throw WireError("reliable fragment group exceeds transfer");
    const auto offset = start * fragment_size;
    const auto size = std::min<std::size_t>(count * fragment_size, transfer.bytes.size() - offset);
    const auto bytes = reader.bytes(size);
    // Acknowledged groups must not be silently replaced with conflicting data.
    for (std::size_t i = 0; i < count; ++i) {
        const auto begin = i * fragment_size;
        const auto length = std::min(fragment_size, size - begin);
        if (transfer.fragments[start + i] && !std::equal(bytes.begin() + begin, bytes.begin() + begin + length, transfer.bytes.begin() + offset + begin)) throw WireError("conflicting reliable fragment duplicate");
    }
    std::copy(bytes.begin(), bytes.end(), transfer.bytes.begin() + offset);
    for (std::size_t i = 0; i < count; ++i) transfer.fragments[start + i] = true;
    if (!std::all_of(transfer.fragments.begin(), transfer.fragments.end(), [](bool present) { return present; })) return;
    auto content = transfer.compressed ? lzss_decompress(transfer.bytes, transfer.uncompressed_size) : transfer.bytes;
    if (transfer.compressed && content.size() != transfer.uncompressed_size) throw WireError("reliable decompressed size mismatch");
    if (!transfer.filename.empty()) {
        result.files.push_back(FileTransfer{transfer.id, transfer.filename, transfer.replay, std::move(content)});
    } else {
        BitReader messages(content);
        auto decoded = decode_messages(messages, true);
        result.messages.insert(result.messages.end(), std::make_move_iterator(decoded.begin()), std::make_move_iterator(decoded.end()));
    }
}
PacketResult Netchannel::receive(std::span<const std::uint8_t> datagram) {
    PacketResult result;
    try {
        if (datagram.size() > config_.max_normal_bytes + 213) throw WireError("datagram exceeds packet limit");
        Bytes packet;
        if (word(datagram) == split_magic) {
            auto assembled = assemble_split(datagram);
            if (!assembled) { result.pending = true; return result; }
            packet = std::move(*assembled);
        } else packet.assign(datagram.begin(), datagram.end());
        if (word(packet) == connectionless_magic) {
            result.connectionless = true;
            result.valid = true;
            result.connectionless_payload.assign(packet.begin() + 4, packet.end());
            return result;
        }
        if (config_.encryption) packet = decrypt_envelope(packet, config_.encryption_key, config_.max_normal_bytes + 128);
        if (word(packet) == compressed_magic) packet = lzss_decompress(std::span(packet).subspan(4), config_.max_normal_bytes + 16);
        if (packet.size() < 12) throw WireError("truncated netchannel header");
        const auto flags = packet[8];
        const auto pad_bits = flags >> 5;
        BitReader reader(packet, packet.size() * 8 - pad_bits);
        result.sequence = reader.bits(32);
        result.ack = reader.bits(32);
        reader.bits(8);
        const auto checksum = reader.bits(16);
        if (checksum != short_checksum(std::span(packet).subspan(11))) throw WireError("packet checksum mismatch");
        const auto reliable_state = static_cast<std::uint8_t>(reader.bits(8));
        const auto choked = flags & 16 ? reader.bits(8) : 0;
        if (!newer(result.sequence, incoming_sequence_)) { result.error = "stale_packet"; return result; }
        if (flags & 14) throw WireError("unsupported netchannel flag bits");
        const auto difference = result.sequence - incoming_sequence_;
        result.dropped = difference > choked + 1 ? difference - choked - 1 : 0;
        // Header sequence acceptance mirrors Source. A rejected fragment does not
        // toggle the incoming reliable bit, so the peer schedules its retransmit.
        if (!config_.passive) acknowledge(result.ack, reliable_state);
        incoming_sequence_ = result.sequence;
        std::optional<unsigned> reliable_channel;
        if (flags & 1) {
            const auto channel = reader.bits(3);
            for (unsigned stream = 0; stream < 2; ++stream) if (reader.bit()) read_transfer(reader, stream, result);
            reliable_channel = channel;
        }
        if (!reader.empty()) {
            auto decoded = decode_messages(reader, false);
            result.messages.insert(result.messages.end(), std::make_move_iterator(decoded.begin()), std::make_move_iterator(decoded.end()));
        }
        if (reliable_channel) {
            incoming_reliable_ ^= static_cast<std::uint8_t>(1u << *reliable_channel);
            for (auto& transfer : incoming_transfers_) {
                if (transfer.active && std::all_of(transfer.fragments.begin(), transfer.fragments.end(), [](bool present) { return present; })) transfer = {};
            }
        }
        result.valid = true;
    } catch (const WireError& error) {
        result.error = error.what();
        result.messages.clear();
        result.files.clear();
    }
    return result;
}
} // namespace hc
