#include <windows.h>
#include "hc/session.hpp"
#include "hc/netchannel.hpp"
#include "hc/state.hpp"
#include "hc/hash.hpp"
#include <atomic>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>

namespace {
using Json=nlohmann::json;
std::atomic<bool> interrupted=false;
BOOL WINAPI stop_handler(DWORD kind){if(kind==CTRL_C_EVENT||kind==CTRL_BREAK_EVENT||kind==CTRL_CLOSE_EVENT){interrupted=true;return TRUE;}return FALSE;}
hc::Bytes from_hex(const std::string&s){if(s.size()%2)throw std::runtime_error("Invalid capture hex");hc::Bytes out;out.reserve(s.size()/2);for(size_t i=0;i<s.size();i+=2){unsigned n{};std::istringstream in(s.substr(i,2));in>>std::hex>>n;if(in.fail()||n>255)throw std::runtime_error("Invalid capture hex");out.push_back(uint8_t(n));}return out;}
std::string to_hex(const hc::Bytes&b){const char*h="0123456789abcdef";std::string out;for(auto n:b){out+=h[n>>4];out+=h[n&15];}return out;}
int decode_capture(const std::string& path,const std::string& output){
    std::ifstream f(path);if(!f)throw std::runtime_error("Capture not found");hc::ChannelConfig passive;passive.passive=true;hc::Netchannel c2s(passive),s2c(passive);Json result={{"host_version",13881},{"server","151.243.93.16:27015"},{"integrity_records",Json::array()},{"messages",Json::array()}};
    hc::State state;
    std::string line;size_t packets=0;while(std::getline(f,line)){if(line.empty())continue;Json record=Json::parse(line);auto direction=record.value("direction",record.value("dir",std::string()));auto hex=record.value("data",record.value("hex",std::string()));if(hex.empty()&&record.contains("payload_hex"))hex=record["payload_hex"];
        auto payload=from_hex(hex);if(payload.size()>=4&&std::all_of(payload.begin(),payload.begin()+4,[](uint8_t v){return v==255;}))continue;
        bool outbound=direction=="c2s"||direction=="client_to_server"||direction=="out";auto& channel=outbound?c2s:s2c;auto parsed=channel.receive(payload);++packets;
        if(!parsed.valid){if(!parsed.pending)result["decode_errors"].push_back({{"packet",packets},{"error",parsed.error}});continue;}
        for(auto&m:parsed.messages){result["messages"].push_back({{"direction",direction},{"type",m.type},{"length",m.bytes.size()}});hc::Proto p(m.bytes);
            if(outbound&&m.type==8&&p.has(1))result["send_table_crc"]=p.get_u32(1);
            if(outbound&&m.type==14)result["integrity_records"].push_back({{"protobuf_hex",to_hex(m.bytes)}});
            if(!outbound&&m.type==7&&p.get_u32(1)==6)result["server_full_signon"]=true;
            if(outbound&&m.type==7&&p.get_u32(1)==6)result["client_full_signon"]=true;
            if(!outbound&&m.type==8){result["map"]=p.get_string(16);result["server_protocol"]=p.get_u32(1);result["map_crc"]=p.get_u32(8);}
            if(!outbound&&(m.type==12||m.type==13)){state.consume(m.type,p,0);auto whitelist=state.string_table_userdata("server_query_info","PureServerWhitelist");if(whitelist){result["pure_whitelist_sha256"]=hc::sha256(*whitelist);result["pure_whitelist_bytes"]=whitelist->size();}}
        }
    }
    result["packet_count"]=packets;std::ofstream out(output);if(!out)throw std::runtime_error("Cannot write extracted capture metadata");out<<result.dump(2)<<'\n';
    std::cout<<Json({{"type","capture_summary"},{"packets",packets},{"has_send_table_crc",result.contains("send_table_crc")},{"client_full_signon",result.value("client_full_signon",false)},{"output",output}}).dump()<<'\n';
    return result.contains("send_table_crc")&&result.value("client_full_signon",false)?0:2;
}
class Reader {
public:
    Reader(){worker=std::thread([this]{std::string line;while(!stop&&std::getline(std::cin,line)){std::lock_guard lock(mutex);if(queue.size()<1024)queue.push_back(std::move(line));}ended=true;});}
    ~Reader(){stop=true;if(worker.joinable()){CancelSynchronousIo(worker.native_handle());worker.join();}}
    bool pop(std::string&line){std::lock_guard lock(mutex);if(queue.empty())return false;line=std::move(queue.front());queue.pop_front();return true;}
    bool eof()const{return ended;}
private:
    std::mutex mutex;std::deque<std::string>queue;std::atomic<bool>stop=false,ended=false;std::thread worker;
};
}
int main(int argc,char**argv){try{
    hc::ClientConfig config;bool json=false,autoconnect=false;int run_seconds=0;
    for(int i=1;i<argc;++i){std::string option=argv[i];auto value=[&]{if(++i>=argc)throw std::runtime_error("Missing value for "+option);return std::string(argv[i]);};
        if(option=="--json")json=true;
        else if(option=="--interactive")json=false;
        else if(option=="--server")config.server=value();
        else if(option=="--profile")config.profile=value();
        else if(option=="--name")config.name=value();
        else if(option=="--auth-helper")config.auth_helper=value();
        else if(option=="--trace")config.trace=true;
        else if(option=="--connect")autoconnect=true;
        else if(option=="--run-seconds"){run_seconds=std::stoi(value());if(run_seconds<1||run_seconds>86400)throw std::runtime_error("Run duration must be 1..86400 seconds");}
        else if(option=="--decode-capture"){auto file=value();auto out=value();return decode_capture(file,out);}
        else if(option=="--help"){std::cout<<"headless-csgo [--interactive|--json] [--server IP:PORT] [--profile FILE]\n  [--name NAME] [--connect] [--trace] [--run-seconds N]\n  --decode-capture CAPTURE_JSONL METADATA_JSON\nCommands: connect, status, team T|CT|spectator, input JSON, weapon ENTITY,\n  buy ITEM, say TEXT, say_team TEXT, aim PITCH YAW, move FORWARD SIDE TICKS, disconnect, quit\n";return 0;}
        else throw std::runtime_error("Unknown option: "+option);
    }
    auto emit=[&](const Json&e){if(json)std::cout<<e.dump()<<'\n';else std::cout<<e.dump(2)<<'\n';std::cout.flush();};
    hc::Session session(config,emit);SetConsoleCtrlHandler(stop_handler,TRUE);Reader reader;
    if(!json)std::cout<<"CS:GO Legacy 1.38.8.1 headless client. Type connect or status.\n";
    if(autoconnect){auto result=session.command("connect");emit({{"type","response"},{"ok",true},{"result",result}});}
    auto started=std::chrono::steady_clock::now();bool quit=false;
    while(!quit&&!interrupted){std::string line;for(unsigned count=0;count<64&&reader.pop(line);++count){if(line.empty())continue;Json id=nullptr;
        try{Json request=json?Json::parse(line):hc::parse_interactive(line);if(!request.is_object())throw std::runtime_error("Request must be an object");id=request.value("id",Json(nullptr));auto op=request.at("op").get<std::string>();auto args=request.value("args",Json::object());auto result=session.command(op,args);emit({{"type","response"},{"id",id},{"ok",true},{"result",result}});if(op=="quit")quit=true;}
        catch(const std::exception&e){emit({{"type","response"},{"id",id},{"ok",false},{"error",{{"message",e.what()}}}});}
    }
        session.poll();
        if(run_seconds&&std::chrono::steady_clock::now()-started>std::chrono::seconds(run_seconds)){emit({{"type","run_complete"},{"status",session.status()}});quit=true;}
        if(reader.eof()&&!run_seconds)quit=true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    session.disconnect("client exit");return 0;
}catch(const std::exception&e){std::cerr<<"headless-csgo: "<<e.what()<<'\n';return 1;}}
