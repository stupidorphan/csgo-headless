#include <windows.h>
#include "hc/accounts.hpp"
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
    Reader(){worker=std::thread([this]{std::string line;while(!stop&&std::getline(std::cin,line)){std::unique_lock lock(mutex);space.wait(lock,[this]{return stop||queue.size()<1024;});if(stop)break;if(!hidden_prompt.empty()){const auto prompt=std::move(hidden_prompt);hidden_prompt.clear();if(console_mode_valid){SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE),console_mode);console_mode_valid=false;}line=std::string("\x01")+"AUTH_INPUT\t"+prompt+"\t"+line;}queue.push_back(std::move(line));}ended=true;});}
    ~Reader(){stop=true;space.notify_all();if(worker.joinable()){CancelSynchronousIo(worker.native_handle());worker.join();}}
    void arm_hidden_prompt(std::string prompt_id){
        std::lock_guard lock(mutex); hidden_prompt=std::move(prompt_id);
        HANDLE input=GetStdHandle(STD_INPUT_HANDLE); DWORD mode=0;
        if(input!=INVALID_HANDLE_VALUE&&GetConsoleMode(input,&mode)){console_mode=mode;console_mode_valid=true;SetConsoleMode(input,mode&~ENABLE_ECHO_INPUT);}
    }
    bool pop(std::string&line){std::lock_guard lock(mutex);if(queue.empty())return false;line=std::move(queue.front());queue.pop_front();space.notify_one();return true;}
    bool eof(){std::lock_guard lock(mutex);return ended&&queue.empty();}
private:
    std::mutex mutex;std::condition_variable space;std::deque<std::string>queue;std::atomic<bool>stop=false,ended=false;std::thread worker;
    std::string hidden_prompt; DWORD console_mode=0; bool console_mode_valid=false;
};
}
int main(int argc,char**argv){try{
    hc::ClientConfig config;bool json=false,autoconnect=false;int run_seconds=0;std::filesystem::path accounts_file;
    for(int i=1;i<argc;++i){std::string option=argv[i];auto value=[&]{if(++i>=argc)throw std::runtime_error("Missing value for "+option);return std::string(argv[i]);};
        if(option=="--json")json=true;
        else if(option=="--interactive")json=false;
        else if(option=="--server")config.server=value();
        else if(option=="--profile")config.profile=value();
        else if(option=="--name")config.name=value();
        else if(option=="--steam-token-file")config.auth_token_file=value();
        else if(option=="--accounts-file")accounts_file=value();
        else if(option=="--trace")config.trace=true;
        else if(option=="--connect")autoconnect=true;
        else if(option=="--run-seconds"){run_seconds=std::stoi(value());if(run_seconds<1||run_seconds>86400)throw std::runtime_error("Run duration must be 1..86400 seconds");}
        else if(option=="--decode-capture"){auto file=value();auto out=value();return decode_capture(file,out);}
        else if(option=="--help"){std::cout<<"headless-csgo [--interactive|--json] [--server IP:PORT] [--profile FILE]\n  [--name NAME] [--accounts-file FILE] [--steam-token-file FILE] [--connect] [--trace] [--run-seconds N]\n  --decode-capture CAPTURE_JSONL METADATA_JSON\nCommands: login [ACCOUNT] qr|password, list, use ACCOUNT, logout, connect [IP:PORT], status,\n  auth qr|password|status|logout, auth_input PROMPT_ID VALUE, team T|CT|spectator,\n  input JSON, weapon ENTITY, buy ITEM, say TEXT, say_team TEXT, aim PITCH YAW,\n  move FORWARD SIDE TICKS, disconnect, quit\n";return 0;}
        else throw std::runtime_error("Unknown option: "+option);
    }
    SetConsoleCtrlHandler(stop_handler,TRUE);if(!json)SetConsoleOutputCP(CP_UTF8);Reader reader;hc::AccountRegistry accounts(accounts_file);std::uint32_t active_account=0;
    if(!config.auth_token_file.empty()){
        // An explicit token file remains supported for single-account scripts.
    }else if(!accounts.empty()){active_account=accounts.accounts().front().id;config.auth_token_file=accounts.get(active_account).token_file;}
    auto emit=[&](const Json&e){
        Json output=e;const auto type=output.value("type",std::string{});if(active_account)output["account"]=active_account;
        if(!json&&(type=="auth_qr"||type=="auth_qr_refresh")){
            std::cout<<output.value("terminal_squares",output.value("terminal_ascii",output.value("terminal",std::string{})))<<"\nScan this URL in Steam: "<<output.value("url",std::string{})<<"\n";std::cout.flush();return;
        }
        if(!json&&type=="auth_prompt"){
            const auto kind=output.value("kind",std::string{"steam_guard"});std::cout<<"Steam authentication prompt ["<<output.value("prompt_id",std::string{})<<"] "<<kind<<": "<<output.value("message",std::string{})<<"\n";std::cout.flush();
            if(kind=="password"||kind=="email_code"||kind=="totp")reader.arm_hidden_prompt(output.value("prompt_id",std::string{}));
            return;
        }
        if(json)std::cout<<output.dump()<<'\n';else std::cout<<output.dump(2)<<'\n';std::cout.flush();
    };
    std::unique_ptr<hc::Session> session;
    auto make_session=[&]{session=std::make_unique<hc::Session>(config,emit);};
    make_session();
    auto switch_account=[&](std::uint32_t id){
        if(!accounts.contains(id))throw std::runtime_error("Unknown account id: "+std::to_string(id));
        if(active_account==id)return;
        if(session&&session->status()["connection"].value("signon",0)!=0)throw std::runtime_error("Disconnect before switching accounts");
        if(session)session->disconnect("account switch");
        active_account=id;config.auth_token_file=accounts.get(id).token_file;session.reset();make_session();
    };
    auto ensure_account=[&](const Json& args){
        if(active_account)return;
        if(!config.auth_token_file.empty())return;
        if(!accounts.empty()){switch_account(accounts.accounts().front().id);return;}
        const auto label=args.value("label",std::string{});switch_account(accounts.create(label));
    };
    auto dispatch=[&](std::string op,Json args)->Json{
        if(op=="list"){
            auto result=Json{{"active_account",active_account},{"accounts",accounts.describe(active_account)}};
            if(active_account&&session){const auto auth=session->status()["auth"];for(auto& item:result["accounts"])if(item["id"]==active_account){item["state"]=auth.value("state",std::string{"signed_out"});if(auth.value("steam_id",std::uint64_t{}))item["steam_id"]=auth["steam_id"];}}
            return result;
        }
        if(op=="login"){
            const auto mode=args.value("mode",std::string{"qr"});if(mode!="qr"&&mode!="password")throw std::runtime_error("Login mode must be qr or password");
            if(args.contains("account"))switch_account(args.at("account").get<std::uint32_t>());else ensure_account(args);
            auto result=session->command("auth",{{"mode",mode}});result["account"]=active_account;return result;
        }
        if(op=="use"){
            switch_account(args.at("account").get<std::uint32_t>());return {{"active_account",active_account}};
        }
        if(op=="logout"){
            if(args.contains("account")){const auto id=args.at("account").get<std::uint32_t>();if(!active_account||active_account!=id)switch_account(id);}
            if(!active_account&&!config.auth_token_file.empty())return session->command("auth_logout",args);
            if(!active_account)throw std::runtime_error("No account selected; use login first");
            return session->command("auth_logout",args);
        }
        if(op=="auth"||op=="auth_input"||op=="auth_status"||op=="auth_logout")ensure_account(args);
        if(op=="connect"&&!active_account&&config.auth_token_file.empty())throw std::runtime_error("No account selected; use login first");
        if(op=="status"){
            auto result=session->command(op,args);result["active_account"]=active_account;return result;
        }
        return session->command(op,args);
    };
    if(!json)std::cout<<"CS:GO Legacy 1.38.8.1 headless client. Type connect or status.\n";
    if(autoconnect){auto result=dispatch("connect",Json::object());emit({{"type","response"},{"ok",true},{"result",result}});}
    auto started=std::chrono::steady_clock::now();bool quit=false;
    while(!quit&&!interrupted){std::string line;for(unsigned count=0;!quit&&count<64&&reader.pop(line);++count){if(line.empty())continue;Json id=nullptr;
        try{Json request; if(!json&&line.rfind(std::string("\x01")+"AUTH_INPUT\t",0)==0){const auto rest=line.substr(12);const auto tab=rest.find('\t');if(tab==std::string::npos)throw std::runtime_error("Hidden authentication input is malformed");request={{"op","auth_input"},{"args",{{"prompt_id",rest.substr(0,tab)},{"value",rest.substr(tab+1)}}}};}else request=json?Json::parse(line):hc::parse_interactive(line);if(!request.is_object())throw std::runtime_error("Request must be an object");id=request.value("id",Json(nullptr));auto op=request.at("op").get<std::string>();auto args=request.value("args",Json::object());auto result=dispatch(op,args);emit({{"type","response"},{"id",id},{"ok",true},{"result",result}});if(op=="quit")quit=true;}
        catch(const std::exception&e){emit({{"type","response"},{"id",id},{"ok",false},{"error",{{"message",e.what()}}}});}
    }
        session->poll();
        if(run_seconds&&std::chrono::steady_clock::now()-started>std::chrono::seconds(run_seconds)){emit({{"type","run_complete"},{"status",session->status()}});quit=true;}
        if(reader.eof()&&!run_seconds)quit=true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    session->disconnect("client exit");return 0;
}catch(const std::exception&e){std::cerr<<"headless-csgo: "<<e.what()<<'\n';return 1;}}
