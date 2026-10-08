#include "hc/proto.hpp"
#include <limits>

namespace hc {
namespace {
uint64_t read_varint(std::span<const uint8_t> s,size_t& pos) {
    uint64_t result=0;
    for(unsigned i=0;i<10;++i) {
        if(pos>=s.size()) throw WireError("truncated protobuf varint");
        uint8_t b=s[pos++];
        if(i==9 && (b&0xfe)) throw WireError("overflowed protobuf varint");
        result|=uint64_t(b&127)<<(i*7);
        if(!(b&128)) return result;
    }
    throw WireError("invalid protobuf varint");
}
}
Proto::Proto(std::span<const uint8_t> bytes):raw_(bytes.begin(),bytes.end()) {
    if(bytes.size()>8*1024*1024) throw WireError("protobuf message exceeds limit");
    size_t pos=0;
    while(pos<bytes.size()) {
        if(fields_.size()>=262144) throw WireError("protobuf field count exceeds limit");
        auto key=read_varint(bytes,pos);
        if((key>>3)==0 || (key>>3)>0x1fffffff) throw WireError("invalid protobuf field number");
        ProtoField f; f.number=uint32_t(key>>3);f.wire_type=uint8_t(key&7);
        size_t len=0;
        if(f.wire_type==0) f.varint=read_varint(bytes,pos);
        else {
            if(f.wire_type==1) len=8;
            else if(f.wire_type==5) len=4;
            else if(f.wire_type==2) { auto n=read_varint(bytes,pos); if(n>bytes.size()-pos) throw WireError("truncated protobuf bytes");len=size_t(n); }
            else throw WireError("unsupported protobuf wire type");
            if(len>bytes.size()-pos) throw WireError("truncated protobuf fixed value");
            f.data.assign(bytes.begin()+pos,bytes.begin()+pos+len);
            if(f.wire_type==1||f.wire_type==5) for(size_t i=0;i<len;++i) f.varint|=uint64_t(bytes[pos+i])<<(8*i);
            pos+=len;
        }
        fields_.push_back(std::move(f));
    }
}
const ProtoField* Proto::last(uint32_t n) const { for(auto i=fields_.rbegin();i!=fields_.rend();++i) if(i->number==n)return &*i;return nullptr; }
bool Proto::has(uint32_t n) const { return last(n)!=nullptr; }
uint64_t Proto::get_u64(uint32_t n,uint64_t d) const { auto f=last(n);return f ? f->varint:d; }
uint32_t Proto::get_u32(uint32_t n,uint32_t d) const { return uint32_t(get_u64(n,d)); }
int32_t Proto::get_i32(uint32_t n,int32_t d) const { return int32_t(get_u64(n,uint32_t(d))); }
float Proto::get_float(uint32_t n,float d) const { auto f=last(n);return f&&f->wire_type==5 ? std::bit_cast<float>(uint32_t(f->varint)):d; }
std::string Proto::get_string(uint32_t n,std::string d) const { auto f=last(n);return f&&f->wire_type==2 ? std::string(f->data.begin(),f->data.end()):d; }
Bytes Proto::get_bytes(uint32_t n,Bytes d) const {auto f=last(n);return f&&f->wire_type==2?f->data:std::move(d);}
std::vector<ProtoField> Proto::fields(uint32_t n)const{std::vector<ProtoField> out;for(auto&f:fields_)if(f.number==n)out.push_back(f);return out;}
std::vector<Proto> Proto::get_messages(uint32_t n)const{std::vector<Proto> out;for(auto&f:fields_)if(f.number==n&&f.wire_type==2)out.emplace_back(f.data);return out;}
void ProtoWriter::varint(uint64_t n){do{auto b=uint8_t(n&127);n>>=7;bytes_.push_back(uint8_t(b|(n?128:0)));}while(n);}
void ProtoWriter::key(uint32_t n,uint8_t type){if(!n||n>0x1fffffff)throw WireError("invalid protobuf field number");varint((uint64_t(n)<<3)|type);}
ProtoWriter& ProtoWriter::u32(uint32_t n,uint32_t v){return u64(n,v);}
ProtoWriter& ProtoWriter::i32(uint32_t n,int32_t v){return u64(n,uint64_t(int64_t(v)));}
ProtoWriter& ProtoWriter::u64(uint32_t n,uint64_t v){key(n,0);varint(v);return *this;}
ProtoWriter& ProtoWriter::fixed32(uint32_t n,uint32_t v){key(n,5);for(unsigned i=0;i<4;++i)bytes_.push_back(uint8_t(v>>(8*i)));return *this;}
ProtoWriter& ProtoWriter::fixed64(uint32_t n,uint64_t v){key(n,1);for(unsigned i=0;i<8;++i)bytes_.push_back(uint8_t(v>>(8*i)));return *this;}
ProtoWriter& ProtoWriter::float32(uint32_t n,float v){return fixed32(n,std::bit_cast<uint32_t>(v));}
ProtoWriter& ProtoWriter::string(uint32_t n,std::string_view v){return bytes(n,std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(v.data()),v.size()));}
ProtoWriter& ProtoWriter::bytes(uint32_t n,std::span<const uint8_t> v){key(n,2);varint(v.size());bytes_.insert(bytes_.end(),v.begin(),v.end());return *this;}
}
