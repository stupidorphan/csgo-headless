#include <winsock2.h>
#include <ws2tcpip.h>
#include "hc/session.hpp"
#include "hc/auth.hpp"
#include "hc/netchannel.hpp"
#include "hc/state.hpp"
#include "hc/usercmd.hpp"
#include "hc/hash.hpp"
#include <algorithm>
#include <array>
#include <cmath>
#include <deque>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace hc {
namespace {
using Clock=std::chrono::steady_clock;
constexpr uint32_t host_version=13881;
constexpr const char* signon_names[]={"disconnected","challenge","connected","new","prespawn","spawn","full","changelevel"};
std::string command_quote(std::string_view s,size_t limit=200){
    if(s.empty()||s.size()>limit)throw std::runtime_error("Text must contain 1.."+std::to_string(limit)+" bytes");
    std::string out="\"";
    for(char c:s){if(static_cast<unsigned char>(c)<32||c=='"'||c=='\\'||c==';')throw std::runtime_error("Unsupported command text character");out+=c;}
    return out+'"';
}
Bytes unhex(std::string_view s){if(s.size()%2)throw WireError("invalid metadata hex");Bytes b;for(size_t i=0;i<s.size();i+=2){unsigned n{};std::istringstream in(std::string(s.substr(i,2)));in>>std::hex>>n;if(in.fail()||n>255)throw WireError("invalid metadata hex");b.push_back(uint8_t(n));}return b;}
}
Proto make_userinfo(std::string_view name,uint32_t rate){
    if(name.empty()||name.size()>63||std::any_of(name.begin(),name.end(),[](unsigned char c){return c<32;}))throw std::runtime_error("Invalid player name");
    ProtoWriter vars;
    std::vector<std::pair<std::string,std::string>> values={{"name",std::string(name)},{"rate","786432"},{"cl_updaterate",std::to_string(rate)},{"cl_cmdrate",std::to_string(rate)},{"cl_interp","0"},{"cl_interp_ratio","2"},{"cl_predict","0"},{"cl_predictweapons","0"},{"cl_lagcompensation","1"},{"cl_dlmax","1200"},{"cl_downloadfilter","none"}};
    for(auto&[k,v]:values){ProtoWriter cv;cv.string(1,k).string(2,v);vars.message(1,cv);}
    ProtoWriter user;user.message(1,vars);return Proto(user.data());
}
Bytes build_connect_packet(uint32_t version,uint32_t challenge,uint64_t steam_id,std::span<const uint8_t> ticket,const Proto& userinfo){
    if(ticket.empty()||ticket.size()>2032)throw WireError("Invalid Steam ticket length");
    BitWriter w;w.bits(0xffffffff,32);w.bits('k',8);w.bits(version,32);w.bits(3,32);w.bits(challenge,32);w.string("");w.string("");w.bits(1,8);
    auto info=encode_message(Message{16,userinfo.data()});w.bytes(info);
    w.bit(false);w.bits(0,32);w.bits(0,32);w.bits(1,8);w.bits(0,32);
    w.bits(uint32_t(ticket.size()+8),16);w.bits(uint32_t(steam_id),32);w.bits(uint32_t(steam_id>>32),32);w.bytes(ticket);
    return w.take();
}
struct Session::Impl {
    ClientConfig config;EventSink sink;Json profile;State state;InputController input;SteamAuth auth;SteamCredentials credentials;
    Netchannel channel;SOCKET socket=INVALID_SOCKET;bool wsa=false;int signon=0;int32_t spawn_count=-1,tick=0;float interval=1.0f/64;
    uint32_t challenge=0;Bytes connect_packet;Clock::time_point started{},last_received{},last_challenge{},next_send{},last_tick_time{};
    std::deque<UserCmd> backups;bool paused=false,awaiting_full_update=false;uint64_t rx=0,tx=0;std::string last_error;size_t integrity_cursor=0;Clock::time_point next_integrity{};
    Impl(ClientConfig c,EventSink e):config(std::move(c)),sink(std::move(e)),auth(config.auth_helper) {
        WSADATA d{};if(WSAStartup(MAKEWORD(2,2),&d))throw std::runtime_error("Winsock initialization failed");wsa=true;
        std::ifstream f(config.profile);if(!f)throw std::runtime_error("Cannot open metadata profile: "+config.profile.string());f>>profile;
        if(profile.value("host_version",0u)!=host_version)throw std::runtime_error("Profile must match Legacy host version 13881");
        state.load_profile(profile);
    }
    ~Impl(){close("client exit");if(wsa)WSACleanup();}
    void emit(std::string_view type,Json payload=Json::object()){if(sink){payload["type"]=type;payload["tick"]=tick;sink(payload);}}
    void send_bytes(std::span<const uint8_t> b){if(socket==INVALID_SOCKET)return;int n=::send(socket,reinterpret_cast<const char*>(b.data()),int(b.size()),0);if(n<0&&WSAGetLastError()!=WSAEWOULDBLOCK)throw std::runtime_error("UDP send failed: "+std::to_string(WSAGetLastError()));if(n>=0)++tx;}
    void queue(uint32_t type,const Proto& p){channel.queue(Message{type,p.data()},true);}
    void stringcmd(std::string_view s){ProtoWriter w;w.string(1,s);queue(5,Proto(w.data()));}
    void confirm(int value){ProtoWriter w;w.u32(1,uint32_t(value)).u32(2,uint32_t(spawn_count));queue(7,Proto(w.data()));}
    void close(std::string reason){
        if(socket!=INVALID_SOCKET){if(signon>=2){try{ProtoWriter w;w.string(1,reason);queue(1,Proto(w.data()));for(auto&d:channel.send())send_bytes(d);}catch(...) {}}closesocket(socket);socket=INVALID_SOCKET;}
        auth.close();if(!credentials.ticket.empty())SecureZeroMemory(credentials.ticket.data(),credentials.ticket.size());credentials={};
        bool was=signon!=0;signon=0;input.reset();backups.clear();channel.reset();state.reset();spawn_count=-1;paused=false;awaiting_full_update=false;integrity_cursor=0;if(!connect_packet.empty())SecureZeroMemory(connect_packet.data(),connect_packet.size());connect_packet.clear();
        if(was)emit("disconnected",{{"reason",reason}});
    }
    void begin(){
        close("reconnect");
        if(!profile.contains("send_table_crc")||!profile["send_table_crc"].is_number_unsigned()||profile["send_table_crc"].get<uint32_t>()==0||!profile.contains("entity_schema")||profile["entity_schema"].value("classes",Json::array()).empty()||!profile.value("bootstrap",Json::object()).value("stock_signon_verified",false)||!profile.value("bootstrap",Json::object()).value("send_table_crc_verified",false))throw std::runtime_error("Bootstrap incomplete: extract a matching demo schema and captured client-info checksum first");
        if(!profile.value("integrity",Json::object()).value("requirements_verified",false))throw std::runtime_error("Bootstrap incomplete: integrity requirements are not verified");
        if(profile["integrity"].value("coverage",Json::object()).value("server",std::string{})!=config.server)throw std::runtime_error("Server differs from verified metadata coverage");
        state.load_profile(profile);credentials=auth.acquire();
        auto colon=config.server.rfind(':');if(colon==std::string::npos)throw std::runtime_error("Server must be a numeric IPv4 address:port");
        sockaddr_in remote{};remote.sin_family=AF_INET;int port=std::stoi(config.server.substr(colon+1));if(port<1||port>65535||inet_pton(AF_INET,config.server.substr(0,colon).c_str(),&remote.sin_addr)!=1)throw std::runtime_error("Invalid IPv4 endpoint");remote.sin_port=htons(uint16_t(port));
        socket=::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);if(socket==INVALID_SOCKET)throw std::runtime_error("Cannot open UDP socket");
        int size=1024*1024;setsockopt(socket,SOL_SOCKET,SO_RCVBUF,reinterpret_cast<const char*>(&size),sizeof(size));
        if(::connect(socket,reinterpret_cast<sockaddr*>(&remote),sizeof(remote))!=0)throw std::runtime_error("Cannot configure UDP peer");u_long nonblocking=1;ioctlsocket(socket,FIONBIO,&nonblocking);
        channel.reset();signon=1;tick=0;challenge=0;rx=tx=0;last_error.clear();started=last_received=Clock::now();last_challenge={};next_send=started;emit("connecting",{{"server",config.server}});send_challenge();
    }
    void send_challenge(){BitWriter w;w.bits(0xffffffff,32);w.bits('q',8);std::ostringstream text;text<<"connect0x"<<std::uppercase<<std::hex<<std::setw(8)<<std::setfill('0')<<challenge;w.string(text.str());send_bytes(w.data());last_challenge=Clock::now();}
    void oob(std::span<const uint8_t> d){
        BitReader r(d);if(r.bits(32)!=0xffffffff)return;auto type=r.bits(8);
        if(type=='A'&&signon==1){
            challenge=r.bits(32);uint32_t protocol=r.bits(32);r.bits(16);r.bits(32);r.bits(32);bool secure=r.bits(8)!=0;auto context=r.string(256);
            if(protocol!=3)throw std::runtime_error("Server did not request supported Steam authentication");
            if(context.rfind("connect",0)!=0)throw std::runtime_error("Unsupported challenge context: "+context);
            uint32_t version=r.bits(32);auto lobby=r.string(256);bool password=r.bits(8)!=0;uint64_t lobby_id=r.bits(32);lobby_id|=uint64_t(r.bits(32))<<32;bool friends=r.bits(8)!=0;bool official=r.bits(8)!=0;bool cert=r.bits(8)!=0;
            if(version!=host_version)throw std::runtime_error("Server version differs from metadata profile");
            if(secure||cert||official||password||friends||lobby_id||!lobby.empty())throw std::runtime_error("Server requires connection features outside this verified Legacy profile");
            if(context=="connect-retry"){send_challenge();return;}
            if(context=="connect-lan-only"||context=="connect-matchmaking-only")throw std::runtime_error("Direct connection rejected: "+context);
            connect_packet=build_connect_packet(version,challenge,credentials.steam_id,credentials.ticket,make_userinfo(config.name));send_bytes(connect_packet);last_challenge=Clock::now();emit("challenge_accepted");
        }else if(type=='B'&&signon==1){
            auto response=r.string(128);if(response.empty()||response[0]!='.')throw WireError("Invalid connection acceptance");
            signon=2;channel.reset();queue(6,make_userinfo(config.name));confirm(2);next_send=Clock::now();emit("signon",{{"state",signon},{"name",signon_names[signon]}});SecureZeroMemory(connect_packet.data(),connect_packet.size());connect_packet.clear();
            SecureZeroMemory(credentials.ticket.data(),credentials.ticket.size());credentials.ticket.clear();
        }else if(type=='9'||type=='l'){auto reason=r.string(4096);if(type=='9')throw std::runtime_error("Server rejected connection: "+reason);emit("print",{{"text",reason}});}
        else if(type=='L')throw std::runtime_error("Server redirect refused; select a server explicitly");
    }
    void change_signon(int value,int32_t count){
        if(value<2||value>7)throw WireError("Invalid signon state");
        if(value==7){signon=7;spawn_count=-1;state.reset();input.reset();backups.clear();confirm(7);emit("map_transition");return;}
        if(value==2&&signon>=2){signon=2;spawn_count=-1;state.reset();state.load_profile(profile);input.reset();backups.clear();}
        else if(value<=signon)return;
        if(spawn_count!=-1&&count!=-1&&count!=spawn_count)throw WireError("Signon spawn count mismatch");
        signon=value;if(count!=-1)spawn_count=count;
        if(value==3){
            ProtoWriter info;info.fixed32(1,profile["send_table_crc"].get<uint32_t>()).u32(2,uint32_t(spawn_count)).u32(3,0).u32(4,0).u32(5,uint32_t(credentials.steam_id)).string(6,config.name);
            for(unsigned i=0;i<4;++i)info.fixed32(7,0);queue(8,Proto(info.data()));
            ProtoWriter progress;progress.u32(1,100);queue(15,Proto(progress.data()));
        }
        if(value==4){auto whitelist=state.string_table_userdata("server_query_info","PureServerWhitelist");auto expected=profile.value("integrity",Json::object()).value("whitelist_sha256",std::string{});if(expected.empty()||!whitelist||sha256(*whitelist)!=expected)throw std::runtime_error("Unsupported integrity requirements: server whitelist differs from verified metadata");}
        if(value==6){integrity_cursor=0;next_integrity=Clock::now();}
        confirm(value);emit("signon",{{"state",signon},{"name",signon_names[signon]}});
        if(value==6)stringcmd("joingame");
    }
    void consume(const Message&m){
        Proto p(m.bytes);if(config.trace)std::cerr<<"rx type="<<m.type<<" bytes="<<m.bytes.size()<<" tick="<<tick<<'\n';
        if(m.type==1)throw std::runtime_error("Server disconnected: "+p.get_string(1));
        if(m.type==4){tick=p.get_i32(1);last_tick_time=Clock::now();}
        else if(m.type==7)change_signon(p.get_i32(1),p.get_i32(2,-1));
        else if(m.type==8){auto coverage=profile["integrity"].value("coverage",Json::object());if(coverage.value("map",std::string{})!=p.get_string(16)||coverage.value("map_crc",0u)!=p.get_u32(8))throw std::runtime_error("Incompatible metadata: server map or checksum differs from verified profile");spawn_count=p.get_i32(2);interval=p.get_float(14,1.0f/64);if(!std::isfinite(interval)||interval<0.001f||interval>0.1f)throw WireError("Invalid server tick interval");state.set_server_info(p.get_string(16),p.get_i32(13),p.get_i32(11),interval);emit("server_info",{{"map",p.get_string(16)},{"tick_interval",interval},{"slot",p.get_i32(13)}});}
        else if(m.type==16)emit("print",{{"text",p.get_string(1)}});
        else if(m.type==11){paused=p.get_u32(1)!=0;emit("pause",{{"paused",paused}});}
        else if(m.type==19){auto angles=p.get_messages(2);if(!angles.empty()){Json a={{"pitch",angles[0].get_float(1)},{"yaw",angles[0].get_float(2)},{"duration_ticks",1}};input.set(a);}}
        else if(m.type==31){std::string name=p.get_string(2);std::string val;uint32_t code=1;auto vars=make_userinfo(config.name,uint32_t(std::round(1/interval))).get_messages(1);if(!vars.empty())for(auto&cv:vars[0].get_messages(1))if(cv.get_string(1)==name){val=cv.get_string(2);code=0;break;}ProtoWriter response;response.u32(1,p.get_u32(1)).u32(2,code).string(3,name).string(4,val);queue(13,Proto(response.data()));}
        bool consumed=state.consume(m.type,p,tick);
        for(auto&[type,out]:state.take_outgoing())queue(type,out);
        for(auto&e:state.take_events())if(sink)sink(e);
        if(m.type==26&&consumed&&signon==5&&!p.get_u32(3)){change_signon(6,spawn_count);next_send=Clock::now();}
        if(m.type==26&&consumed&&!p.get_u32(3))awaiting_full_update=false;
        if(state.needs_full_update()){awaiting_full_update=true;state.clear_full_update_request();}
    }
    void poll(){
        if(socket==INVALID_SOCKET)return;
        try{
            std::array<uint8_t,65536> buffer{};
            for(unsigned packets=0;packets<256;++packets){int n=recv(socket,reinterpret_cast<char*>(buffer.data()),int(buffer.size()),0);if(n<0){if(WSAGetLastError()==WSAEWOULDBLOCK)break;throw std::runtime_error("UDP receive failed: "+std::to_string(WSAGetLastError()));}if(!n)continue;++rx;
                std::span<const uint8_t>d(buffer.data(),size_t(n));
                if(d.size()>=4&&d[0]==255&&d[1]==255&&d[2]==255&&d[3]==255){oob(d);last_received=Clock::now();}
                else if(signon>=2){auto result=channel.receive(d);if(result.valid){last_received=Clock::now();for(auto&m:result.messages)consume(m);}else if(!result.pending&&!result.error.empty()){if(config.trace)std::cerr<<"discarded packet: "<<result.error<<'\n';}}
            }
            auto now=Clock::now();if(now-last_received>std::chrono::seconds(signon==6?30:120))throw std::runtime_error("Server connection timed out");
            if(signon==6&&now>=next_integrity&&profile.contains("integrity_records")){auto&records=profile["integrity_records"];for(unsigned count=0;count<5&&integrity_cursor<records.size();++count,++integrity_cursor)queue(14,Proto(unhex(records[integrity_cursor].at("protobuf_hex").get<std::string>())));next_integrity=now+std::chrono::milliseconds(200);}
            if(signon==1){if(now-last_challenge>std::chrono::seconds(2)){if(now-started>std::chrono::seconds(30))throw std::runtime_error("Connection handshake timed out");if(connect_packet.empty())send_challenge();else{send_bytes(connect_packet);last_challenge=now;}}return;}
            if(now>=next_send){
                std::vector<Message> unreliable;
                ProtoWriter ack;ack.i32(1,awaiting_full_update?-1:state.entity_tick());unreliable.push_back({4,ack.take()});
                if(signon==6&&!paused){
                    int32_t estimated=tick;if(last_tick_time!=Clock::time_point{})estimated+=int32_t(std::chrono::duration<double>(now-last_tick_time).count()/interval);
                    const auto due=unsigned(std::min(15.0,std::floor(std::chrono::duration<double>(now-next_send).count()/interval)+1));
                    std::vector<UserCmd> backup(backups.begin(),backups.end()),fresh;
                    for(unsigned index=0;index<due;++index){auto cmd=input.next(estimated-int32_t(due-1-index));fresh.push_back(cmd);backups.push_back(cmd);while(backups.size()>2)backups.pop_front();}
                    auto move=make_move(backup,fresh);unreliable.push_back({9,move.data()});
                    next_send+=std::chrono::duration_cast<Clock::duration>(std::chrono::duration<double>(due*interval));
                }
                for(auto&d:channel.send(unreliable))send_bytes(d);if(signon!=6||paused)next_send=now+std::chrono::duration_cast<Clock::duration>(std::chrono::duration<double>(signon==6?interval:0.2));
            }
        }catch(const std::exception&e){last_error=e.what();emit("error",{{"message",last_error}});close(last_error);}
    }
};
Session::Session(ClientConfig c,EventSink sink):impl_(std::make_unique<Impl>(std::move(c),std::move(sink))){}
Session::~Session()=default;
void Session::poll(){impl_->poll();}
void Session::disconnect(std::string r){impl_->close(std::move(r));}
Json Session::status()const{auto result=impl_->state.status();result["connection"]={{"state",signon_names[impl_->signon]},{"signon",impl_->signon},{"server",impl_->config.server},{"tick",impl_->tick},{"received_packets",impl_->rx},{"sent_packets",impl_->tx},{"last_error",impl_->last_error}};return result;}
Json Session::command(std::string_view op,const Json&a){
    if(!a.is_object())throw std::runtime_error("args must be an object");
    if(op=="connect"){try{impl_->begin();}catch(...){impl_->close("connection initialization failed");throw;}return {{"state","connecting"}};}
    if(op=="status")return status();
    if(op=="disconnect"||op=="quit"){disconnect();return {{"state","disconnected"}};}
    if(impl_->signon!=6)throw std::runtime_error("Gameplay commands require full signon");
    if(op=="input")impl_->input.set(a);
    else if(op=="weapon"){auto entity=a.at("entity").get<unsigned>();if(entity==0||entity>=2048)throw std::runtime_error("Weapon entity must be 1..2047");impl_->input.select_weapon(uint16_t(entity));}
    else if(op=="team"){auto team=a.at("team").get<std::string>();int id=team=="T"||team=="t"?2:team=="CT"||team=="ct"?3:team=="spectator"?1:0;if(!id)throw std::runtime_error("Team must be T, CT, or spectator");impl_->stringcmd("jointeam "+std::to_string(id));}
    else if(op=="buy"){auto item=a.at("item").get<std::string>();if(item.empty()||item.size()>64||!std::all_of(item.begin(),item.end(),[](unsigned char c){return std::isalnum(c)||c=='_';}))throw std::runtime_error("Invalid buy item");impl_->stringcmd("buy "+item);}
    else if(op=="say"||op=="say_team")impl_->stringcmd(std::string(op)+" "+command_quote(a.at("text").get<std::string>()));
    else throw std::runtime_error("Unknown operation: "+std::string(op));
    return {{"accepted",true}};
}
Json parse_interactive(std::string_view line){
    std::istringstream in{std::string(line)};std::string op;in>>op;Json args=Json::object();
    if(op=="team"){std::string v;in>>v;args["team"]=v;}
    else if(op=="weapon"){unsigned id{};if(!(in>>id))throw std::runtime_error("Usage: weapon ENTITY");args["entity"]=id;}
    else if(op=="buy"){std::string v;in>>v;args["item"]=v;}
    else if(op=="say"||op=="say_team"){std::string v;std::getline(in>>std::ws,v);args["text"]=v;}
    else if(op=="input"){std::string v;std::getline(in>>std::ws,v);args=Json::parse(v);}
    else if(op=="aim"){float pitch{},yaw{};if(!(in>>pitch>>yaw))throw std::runtime_error("Usage: aim PITCH YAW");op="input";args={{"pitch",pitch},{"yaw",yaw},{"duration_ticks",1}};}
    else if(op=="move"){float forward{},side{};unsigned ticks{};if(!(in>>forward>>side>>ticks))throw std::runtime_error("Usage: move FORWARD SIDE TICKS");op="input";args={{"forward",forward},{"side",side},{"duration_ticks",ticks}};}
    if(op.empty())throw std::runtime_error("Empty command");return {{"op",op},{"args",args}};
}
}
