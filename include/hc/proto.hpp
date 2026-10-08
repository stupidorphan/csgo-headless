#pragma once
#include <bit>
#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include "hc/wire.hpp"

namespace hc {
struct ProtoField {
    uint32_t number = 0;
    uint8_t wire_type = 0;
    uint64_t varint = 0;
    Bytes data;
};
class Proto {
public:
    Proto() = default;
    explicit Proto(std::span<const uint8_t> bytes);
    bool has(uint32_t field) const;
    uint64_t get_u64(uint32_t field, uint64_t fallback=0) const;
    uint32_t get_u32(uint32_t field, uint32_t fallback=0) const;
    int32_t get_i32(uint32_t field, int32_t fallback=0) const;
    float get_float(uint32_t field, float fallback=0) const;
    std::string get_string(uint32_t field, std::string fallback={}) const;
    Bytes get_bytes(uint32_t field, Bytes fallback={}) const;
    std::vector<Proto> get_messages(uint32_t field) const;
    std::vector<ProtoField> fields(uint32_t field) const;
    const Bytes& data() const { return raw_; }
    const std::vector<ProtoField>& all_fields() const { return fields_; }
private:
    const ProtoField* last(uint32_t field) const;
    Bytes raw_;
    std::vector<ProtoField> fields_;
};
class ProtoWriter {
public:
    ProtoWriter& u32(uint32_t field,uint32_t value);
    ProtoWriter& i32(uint32_t field,int32_t value);
    ProtoWriter& u64(uint32_t field,uint64_t value);
    ProtoWriter& fixed32(uint32_t field,uint32_t value);
    ProtoWriter& fixed64(uint32_t field,uint64_t value);
    ProtoWriter& float32(uint32_t field,float value);
    ProtoWriter& string(uint32_t field,std::string_view value);
    ProtoWriter& bytes(uint32_t field,std::span<const uint8_t> value);
    ProtoWriter& message(uint32_t field,const Proto& value) { return bytes(field,value.data()); }
    ProtoWriter& message(uint32_t field,const ProtoWriter& value) { return bytes(field,value.data()); }
    const Bytes& data() const { return bytes_; }
    Bytes take() { return std::move(bytes_); }
private:
    void key(uint32_t field,uint8_t type);
    void varint(uint64_t value);
    Bytes bytes_;
};
}
