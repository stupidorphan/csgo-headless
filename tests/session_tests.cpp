#include "hc/session.hpp"
#include "hc/netchannel.hpp"
#include "hc/hash.hpp"
#include <iostream>
#include <stdexcept>
static void check(bool b){if(!b)throw std::runtime_error("session assertion failed");}
int main(){try{
    check(hc::sha256({})=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    auto q=hc::parse_interactive("team CT");check(q["op"]=="team"&&q["args"]["team"]=="CT");
    q=hc::parse_interactive("say hello world");check(q["args"]["text"]=="hello world");
    q=hc::parse_interactive("move 1 -0.5 64");check(q["args"]["duration_ticks"]==64);
    auto info=hc::make_userinfo("test");check(info.get_messages(1).at(0).get_messages(1).at(0).get_string(1)=="name");
    hc::Bytes ticket={1,2,3,4};auto packet=hc::build_connect_packet(13881,0xabcdef,0x1122334455667788,ticket,info);hc::BitReader r(packet);
    check(r.bits(32)==0xffffffff&&r.bits(8)=='k'&&r.bits(32)==13881&&r.bits(32)==3&&r.bits(32)==0xabcdef);check(r.string().empty()&&r.string().empty()&&r.bits(8)==1);
    check(r.varuint32()==16);auto bytes=r.varuint32();hc::Proto user(r.bytes(bytes));check(user.get_messages(1).size()==1);
    check(!r.bit());check(r.bits(32)==0&&r.bits(32)==0&&r.bits(8)==1&&r.bits(32)==0);check(r.bits(16)==12&&r.bits(32)==0x55667788&&r.bits(32)==0x11223344);check(r.bytes(4)==ticket);
    std::cout<<"session request and connection framing tests passed\n";return 0;
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}
