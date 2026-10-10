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
    Reader(){worker=std::thread([this]{std::string line;while(!stop&&std::getline(std::cin,line)){std::unique_lock lock(mutex);space.wait(lock,[this]{return stop||queue.size()<1024;});if(stop)break;if(!hidden_prompt.empty()){const auto prompt=std::move(hidden_prompt);hidden_prompt.clear();if(console_mode_valid){SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE),console_mode);console_mode_valid=false;std::cout<<'\n';std::cout.flush();}line=std::string("\x01")+"AUTH_INPUT\t"+prompt+"\t"+line;}queue.push_back(std::move(line));}ended=true;});}
    ~Reader(){stop=true;space.notify_all();if(worker.joinable()){CancelSynchronousIo(worker.native_handle());worker.join();}}
    void arm_prompt(std::string prompt_id, bool hide_echo = false){
        std::lock_guard lock(mutex); hidden_prompt=std::move(prompt_id);
        if(hide_echo){
            HANDLE input=GetStdHandle(STD_INPUT_HANDLE); DWORD mode=0;
            if(input!=INVALID_HANDLE_VALUE&&GetConsoleMode(input,&mode)){console_mode=mode;console_mode_valid=true;SetConsoleMode(input,mode&~ENABLE_ECHO_INPUT);}
        }
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
        else if(option=="--strict")config.strict_profile=true;
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
    std::map<std::uint32_t, std::unique_ptr<hc::Session>> sessions;
    bool swarm_mode=false;
    std::unordered_map<std::uint32_t, std::string> last_auth_state;
    std::unordered_map<std::uint32_t, bool> last_remote_interaction;
    auto emit=[&](const Json&e){
        Json output=e;const auto type=output.value("type",std::string{});
        if(!output.contains("account")&&active_account)output["account"]=active_account;
        if(json){std::cout<<output.dump()<<'\n';std::cout.flush();return;}
        const auto acc_id=output.value("account",active_account);
        std::string prefix;
        if(acc_id!=0&&(accounts.accounts().size()>1||sessions.size()>1)){
            std::string label;
            if(accounts.contains(acc_id))label=accounts.get(acc_id).label;
            if(!label.empty())prefix="[#"+std::to_string(acc_id)+" "+label+"] ";
            else prefix="[#"+std::to_string(acc_id)+"] ";
        }
        if(type=="auth_qr"||type=="auth_qr_refresh"){
            std::cout<<output.value("terminal",output.value("terminal_squares",output.value("terminal_ascii",std::string{})))<<"\nScan this QR code with the Steam Mobile App QR scanner (or URL: "<<output.value("url",std::string{})<<")\n";std::cout.flush();return;
        }
        if(type=="auth_prompt"){
            const auto kind=output.value("kind",std::string{"steam_guard"});
            const auto prompt_id=output.value("prompt_id",std::string{});
            const auto msg=output.value("message",std::string{});
            if(kind=="account_name"){
                std::cout<<"Steam account username: ";std::cout.flush();
                reader.arm_prompt(prompt_id, false);
            } else if(kind=="password"){
                std::cout<<"Steam password: ";std::cout.flush();
                reader.arm_prompt(prompt_id, true);
            } else if(kind=="email_code"){
                if(!msg.empty()) std::cout<<"["<<msg<<"]\n";
                std::cout<<"Enter Steam Guard code (email): ";std::cout.flush();
                reader.arm_prompt(prompt_id, false);
            } else if(kind=="totp"||kind=="steam_guard_code"||kind=="mobile_confirmation"){
                if(!msg.empty()) std::cout<<"["<<msg<<"]\n";
                std::cout<<"Enter Steam Guard code: ";std::cout.flush();
                reader.arm_prompt(prompt_id, false);
            } else {
                std::cout<<"Steam Guard code"<<(msg.empty()?"":": "+msg)<<"\nEnter code: ";std::cout.flush();
                reader.arm_prompt(prompt_id, false);
            }
            return;
        }
        if(type=="auth_state"){
            const auto st=output.value("state",std::string{});
            const bool remote=output.value("had_remote_interaction",false);
            if(remote&&!last_remote_interaction[acc_id]){
                last_remote_interaction[acc_id]=true;
                std::cout<<prefix<<"[Auth] Confirmation notification acknowledged.\n";std::cout.flush();
            }
            if(st!=last_auth_state[acc_id]){
                last_auth_state[acc_id]=st;
                if(st=="qr_pending")std::cout<<prefix<<"[Auth] Waiting for QR code scan...\n";
                else if(st=="guard_pending")std::cout<<prefix<<"[Auth] Awaiting Steam Guard code...\n";
                else if(st=="cm_connecting")std::cout<<prefix<<"[Auth] Connecting to Steam CM servers...\n";
                else if(st=="authenticated")std::cout<<prefix<<"[Auth] Authenticated successfully with Steam!\n";
                else if(st=="signed_out")std::cout<<prefix<<"[Auth] Signed out.\n";
                std::cout.flush();
            }
            return;
        }
        if(type=="auth_completed"){
            last_auth_state[acc_id]="authenticated";
            std::cout<<prefix<<"[Auth] Login complete! SteamID: "<<output.value("steam_id",std::uint64_t{})<<'\n';std::cout.flush();return;
        }
        if(type=="auth_error"){
            std::cout<<prefix<<"[Auth Error] "<<output.value("message","Authentication error");
            const auto retry=output.value("retry_in_ms",0);
            if(retry>0)std::cout<<" (retrying in "<<(retry/1000)<<"s)";
            std::cout<<'\n';std::cout.flush();return;
        }
        if(type=="connecting"){
            std::cout<<prefix<<"[Net] Connecting to "<<output.value("server","")<<"...\n";std::cout.flush();return;
        }
        if(type=="challenge_accepted"){
            std::cout<<prefix<<"[Net] Server challenge accepted, establishing session...\n";std::cout.flush();return;
        }
        if(type=="signon"){
            std::cout<<prefix<<"[Net] Signon: "<<output.value("name","")<<" ("<<output.value("state",0)<<"/6)\n";std::cout.flush();return;
        }
        if(type=="server_info"){
            std::cout<<prefix<<"[Game] Server map: "<<output.value("map","")<<" | Slot: "<<output.value("slot",0)<<'\n';std::cout.flush();return;
        }
        if(type=="map_transition"){
            std::cout<<prefix<<"[Game] Map changing...\n";std::cout.flush();return;
        }
        if(type=="pause"){
            std::cout<<prefix<<(output.value("paused",false)?"[Game] Match paused.\n":"[Game] Match unpaused.\n");std::cout.flush();return;
        }
        if(type=="print"){
            std::cout<<prefix<<output.value("text","")<<'\n';std::cout.flush();return;
        }
        if(type=="disconnected"){
            std::cout<<prefix<<"[Net] Disconnected: "<<output.value("reason","unknown")<<'\n';std::cout.flush();return;
        }
        if(type=="error"){
            std::cout<<prefix<<"[Net Error] "<<output.value("message","unknown error")<<'\n';std::cout.flush();return;
        }
        if(type=="run_complete"){
            std::cout<<"Run complete.\n";std::cout.flush();return;
        }
        if(type=="response"){
            const bool ok=output.value("ok",false);
            if(!ok){
                const auto err=output.value("error",Json::object()).value("message","Unknown error");
                std::cout<<"[Error] "<<err<<'\n';std::cout.flush();return;
            }
            const auto result=output.value("result",Json::object());
            if(result.contains("help")){
                std::cout<<result["help"].get<std::string>()<<'\n';std::cout.flush();return;
            }
            if(result.contains("local_steam_accounts")){
                const auto& list=result["local_steam_accounts"];
                if(list.empty()){
                    std::cout<<"No local Steam accounts found in Steam configuration.\n";
                }else{
                    std::cout<<"--- Detected Local Steam Accounts ---\n";
                    for(size_t idx=0;idx<list.size();++idx){
                        const auto& acc=list[idx];
                        std::cout<<"  ["<<(idx+1)<<"] "<<acc.value("account_name","")
                                 <<" (SteamID: "<<acc.value("steam_id","")<<")";
                        const auto persona=acc.value("persona_name","");
                        if(!persona.empty())std::cout<<" - \""<<persona<<"\"";
                        if(acc.value("auto_login",false))std::cout<<" [AutoLogin]";
                        std::cout<<'\n';
                    }
                    std::cout<<"Tip: Run 'import local' to configure all of them, or 'login <username>' to authenticate.\n";
                }
                std::cout.flush();return;
            }
            if(result.contains("imported_local_accounts")){
                const auto& list=result["imported_local_accounts"];
                const auto active_id=result.value("active_account",active_account);
                std::cout<<"--- Imported Local Steam Accounts ---\n";
                for(const auto& acc:list){
                    const auto id=acc.value("id",0u);
                    const bool is_active=(id==active_id);
                    std::cout<<(is_active?" * [":"   [")<<id<<"] "
                             <<acc.value("account_name","")
                             <<" (SteamID: "<<acc.value("steam_id","")<<")";
                    const auto persona=acc.value("persona_name","");
                    if(!persona.empty())std::cout<<" - \""<<persona<<"\"";
                    if(acc.value("auto_login",false))std::cout<<" [AutoLogin]";
                    if(is_active)std::cout<<" [Active]";
                    std::cout<<'\n';
                }
                std::cout<<"All local accounts are now configured. Type 'login <username>' or 'login <id>' to sign in.\n";
                std::cout.flush();return;
            }
            if(result.contains("swarm_connect")){
                std::cout<<"Connecting swarm to "<<result.value("server","")<<"...\n";
                for(const auto& item:result["swarm_connect"]){
                    const auto id=item.value("id",0u);
                    std::string label;
                    if(id&&accounts.contains(id))label=" ("+accounts.get(id).label+")";
                    if(item.contains("error")){
                        std::cout<<"  Account #"<<id<<label<<": Error - "<<item["error"].get<std::string>()<<'\n';
                    }else{
                        std::cout<<"  Account #"<<id<<label<<": Connecting...\n";
                    }
                }
                std::cout.flush();return;
            }
            if(result.contains("swarm_disconnect")){
                std::cout<<"Disconnected all swarm sessions ("<<result["swarm_disconnect"].size()<<" accounts).\n";
                std::cout.flush();return;
            }
            if(result.contains("swarm_status")){
                const bool sm=result.value("swarm_mode",false);
                std::cout<<"=== Swarm Status (Mode: "<<(sm?"ENABLED":"disabled")<<") ===\n";
                for(const auto& item:result["swarm_status"]){
                    const auto id=item.value("id",0u);
                    const auto label=item.value("label",std::string{});
                    const auto& conn=item.value("connection",Json::object());
                    const auto& auth=item.value("auth",Json::object());
                    const auto signon=conn.value("signon",0);
                    std::cout<<"  #"<<id<<(label.empty()?"":" ["+label+"]");
                    const auto sid=auth.value("steam_id",std::uint64_t{});
                    if(sid)std::cout<<" (SteamID: "<<sid<<")";
                    std::cout<<"\n    Auth: "<<auth.value("state","signed_out")
                             <<" | Net: "<<conn.value("state","disconnected");
                    if(signon>0){
                        std::cout<<" (Signon: "<<signon<<"/6, Map: "<<conn.value("map","none")<<")";
                    }
                    if(item.contains("local")&&!item["local"].is_null()){
                        const auto& loc=item["local"];
                        std::cout<<"\n    Player: "<<loc.value("health",0)<<" HP | "
                                 <<loc.value("armor",0)<<" Armor | $"<<loc.value("money",0);
                    }
                    std::cout<<'\n';
                }
                std::cout.flush();return;
            }
            if(result.contains("swarm_mode")&&result.size()==1){
                const bool en=result["swarm_mode"].get<bool>();
                if(en){
                    std::cout<<"[Swarm] Swarm mode ENABLED. Gameplay commands (team, buy, say, aim, move) will broadcast to all accounts.\n";
                }else{
                    std::cout<<"[Swarm] Swarm mode DISABLED. Commands apply only to active account (#"<<active_account<<").\n";
                }
                std::cout.flush();return;
            }
            if(result.contains("broadcast")){
                const auto cmd=result.value("broadcast","");
                unsigned success=0,failed=0;
                for(const auto& item:result["results"]){
                    if(item.value("ok",false))++success;else ++failed;
                }
                std::cout<<"[Broadcast] '"<<cmd<<"' executed across "<<success<<" session(s)";
                if(failed>0)std::cout<<" ("<<failed<<" failed/not in-game)";
                std::cout<<".\n";
                std::cout.flush();return;
            }
            if(result.contains("accounts")){
                const auto active_id=result.value("active_account",active_account);
                const bool sm=result.value("swarm_mode",swarm_mode);
                std::cout<<"--- Managed Accounts (Swarm: "<<(sm?"ENABLED":"disabled")<<") ---\n";
                for(const auto& a:result["accounts"]){
                    const auto id=a.value("id",0u);
                    const bool is_active=(id==active_id);
                    std::cout<<(is_active?" * [":"   [")<<id<<"] "
                             <<a.value("label","unnamed");
                    const auto st=a.value("state","signed_out");
                    std::cout<<" ("<<st<<")";
                    const auto net=a.value("net_state","disconnected");
                    if(net!="disconnected"){
                        std::cout<<" [Net: "<<net;
                        if(a.contains("signon"))std::cout<<" ("<<a["signon"]<<"/6)";
                        std::cout<<"]";
                    }
                    const auto sid=a.value("steam_id",std::uint64_t{});
                    if(sid)std::cout<<" SteamID: "<<sid;
                    if(is_active)std::cout<<" [Active]";
                    std::cout<<'\n';
                }
                std::cout<<"Commands: use <id> | connect_all [ip:port] | broadcast <cmd> | swarm [on/off]\n";
                std::cout.flush();return;
            }
            if(result.contains("active_account")&&result.size()==1){
                std::cout<<"Switched active account to #"<<result["active_account"]<<".\n";
                std::cout.flush();return;
            }
            if(result.value("state","")=="authenticating"){
                std::cout<<"[Auth] Starting "<<result.value("mode","auth")<<" login for account #"
                         <<output.value("account",active_account)<<"...\n";
                std::cout.flush();return;
            }
            if(result.value("state","")=="importing"){
                std::cout<<"[Auth] Importing token for account #"<<output.value("account",active_account)<<"...\n";
                std::cout.flush();return;
            }
            if(result.value("state","")=="signed_out"){
                std::cout<<"[Auth] Logged out account #"<<output.value("account",active_account)<<".\n";
                std::cout.flush();return;
            }
            if(result.contains("server")&&result.value("state","")=="connecting"){
                std::cout<<"Connecting to "<<result["server"]<<"...\n";
                std::cout.flush();return;
            }
            if(result.contains("connection")){
                const auto& conn=result["connection"];
                const auto& auth=result.value("auth",Json::object());
                const auto acc_id=output.value("account",result.value("active_account",active_account));
                std::cout<<"--- Client Status ---\n";
                std::cout<<"  Account:    #"<<acc_id;
                const auto sid=auth.value("steam_id",std::uint64_t{});
                if(sid)std::cout<<" (SteamID: "<<sid<<")";
                std::cout<<'\n';
                std::cout<<"  Auth:       "<<auth.value("state","signed_out")<<'\n';
                std::cout<<"  Connection: "<<conn.value("state","disconnected");
                const auto srv=conn.value("server","");
                if(!srv.empty())std::cout<<" ["<<srv<<"]";
                std::cout<<'\n';
                const auto signon=conn.value("signon",0);
                if(signon>0){
                    std::cout<<"  Signon:     "<<signon<<"/6 | Tick: "<<conn.value("tick",0);
                    const auto map_name=conn.value("map","");
                    if(!map_name.empty())std::cout<<" | Map: "<<map_name;
                    std::cout<<" | Rx: "<<conn.value("received_packets",0)
                             <<" | Tx: "<<conn.value("sent_packets",0)<<'\n';
                }
                const auto err=conn.value("last_error","");
                if(!err.empty())std::cout<<"  Last Error: "<<err<<'\n';
                if(result.contains("local")&&!result["local"].is_null()){
                    const auto& loc=result["local"];
                    std::cout<<"  Player:     "<<loc.value("health",0)<<" HP | "
                             <<loc.value("armor",0)<<" Armor | $"<<loc.value("money",0)<<'\n';
                }
                std::cout.flush();return;
            }
            if(result.value("accepted",false)){
                std::cout<<"OK\n";std::cout.flush();return;
            }
            if(result.value("state","")=="disconnected"){
                std::cout<<"Disconnected.\n";std::cout.flush();return;
            }
            if(!result.empty()){
                std::cout<<result.dump()<<'\n';std::cout.flush();
            }
            return;
        }
        std::cout<<output.dump()<<'\n';std::cout.flush();
    };
    auto get_session=[&](std::uint32_t id)->hc::Session&{
        auto it=sessions.find(id);
        if(it!=sessions.end())return *it->second;
        hc::ClientConfig cfg=config;
        if(id!=0&&accounts.contains(id)){
            cfg.auth_token_file=accounts.get(id).token_file;
            const auto label=accounts.get(id).label;
            if(!label.empty()&&config.name.empty()){
                cfg.name=label;
            }
        }
        auto sess=std::make_unique<hc::Session>(cfg,[emit,id](Json e){
            if(id!=0&&!e.contains("account")){
                e["account"]=id;
            }
            emit(e);
        });
        auto [inserted,_]=sessions.emplace(id,std::move(sess));
        return *inserted->second;
    };
    get_session(active_account);
    auto switch_account=[&](std::uint32_t id){
        if(!accounts.contains(id))throw std::runtime_error("Unknown account id: "+std::to_string(id));
        active_account=id;
        config.auth_token_file=accounts.get(id).token_file;
        get_session(id);
    };
    auto ensure_account=[&](const Json& args){
        if(args.contains("label")&&!args["label"].get<std::string>().empty()){
            const auto label=args.value("label",std::string{});
            for(const auto& acc:accounts.accounts()){if(acc.label==label){switch_account(acc.id);return;}}
            switch_account(accounts.create(label));
            return;
        }
        if(active_account)return;
        if(!config.auth_token_file.empty())return;
        if(!accounts.empty()){switch_account(accounts.accounts().front().id);return;}
        const auto label=args.value("label",std::string{});switch_account(accounts.create(label));
    };
    auto dispatch=[&](std::string op,Json args)->Json{
        if(op=="help"){
            return {{"help",
                "Available Commands:\n"
                "  login [username] [password]    Log into Steam (credentials or QR)\n"
                "  local_accounts                 List Steam accounts found on this PC\n"
                "  import local                   Import all local Steam accounts into client\n"
                "  import <token_or_file> [user]  Import saved Steam refresh token\n"
                "  list                           List managed client accounts\n"
                "  use <id>                       Switch active account (e.g. use 1)\n"
                "  new / add <label>              Create new account slot (e.g. add alt)\n"
                "  logout                         Log out active account\n"
                "  status                         Show connection, auth, and player state\n"
                "  connect [ip:port]              Connect active account to game server\n"
                "  disconnect                     Disconnect active account\n"
                "  connect_all [ip:port]          Connect all accounts to game server\n"
                "  disconnect_all                 Disconnect all accounts from game server\n"
                "  status_all                     Show status of all swarm sessions\n"
                "  swarm [on|off]                 Toggle automatic swarm broadcast mode\n"
                "  broadcast <command>            Execute command on all accounts\n"
                "  team <T|CT|spectator>          Join a team (e.g. team CT)\n"
                "  buy <item>                     Buy weapon/item (e.g. buy ak47)\n"
                "  say <message>                  Send chat message\n"
                "  say_team <message>             Send team chat message\n"
                "  weapon <entity_id>             Select weapon entity\n"
                "  aim <pitch> <yaw>              Set aim angles\n"
                "  move <forward> <side> <ticks>  Send movement input\n"
                "  quit                           Exit client"}};
        }
        if(op=="list"){
            auto result=Json{{"active_account",active_account},{"accounts",accounts.describe(active_account)},{"swarm_mode",swarm_mode}};
            for(auto& item:result["accounts"]){
                const auto id=item.value("id",0u);
                auto it=sessions.find(id);
                if(it!=sessions.end()){
                    const auto st=it->second->status();
                    const auto auth=st.value("auth",Json::object());
                    const auto conn=st.value("connection",Json::object());
                    item["state"]=auth.value("state",std::string{"signed_out"});
                    if(auth.value("steam_id",std::uint64_t{}))item["steam_id"]=auth["steam_id"];
                    item["net_state"]=conn.value("state","disconnected");
                    if(conn.value("signon",0)>0)item["signon"]=conn["signon"];
                }
            }
            return result;
        }
        if(op=="account_add"||op=="new"||op=="add"){
            const auto label=args.value("label",std::string{});
            const auto id=accounts.create(label);
            switch_account(id);
            return {{"account",id},{"active_account",active_account},{"accounts",accounts.describe(active_account)}};
        }
        auto read_local_steam_accounts = []() -> std::vector<Json> {
            std::vector<Json> detected;
            const std::filesystem::path paths[] = {
                "C:/Program Files (x86)/Steam/config/loginusers.vdf",
                "C:/Program Files/Steam/config/loginusers.vdf"
            };
            for (const auto& p : paths) {
                std::error_code ec;
                if (!std::filesystem::exists(p, ec)) continue;
                std::ifstream f(p);
                std::string line;
                std::string current_id, current_account, current_persona;
                bool autologin = false;
                while (std::getline(f, line)) {
                    if (line.find('{') != std::string::npos || line.find('}') != std::string::npos) {
                        if (line.find('}') != std::string::npos && !current_account.empty()) {
                            detected.push_back({{"steam_id", current_id}, {"account_name", current_account},
                                                {"persona_name", current_persona}, {"auto_login", autologin}});
                            current_id.clear(); current_account.clear(); current_persona.clear(); autologin = false;
                        }
                        continue;
                    }
                    if (line.find("\"7656") != std::string::npos) {
                        const auto start = line.find("\"7656") + 1;
                        const auto end = line.find('"', start);
                        if (end != std::string::npos) current_id = line.substr(start, end - start);
                    }
                    if (line.find("\"AccountName\"") != std::string::npos) {
                        const auto tab = line.find("\"AccountName\"");
                        const auto val_start = line.find('"', tab + 13);
                        if (val_start != std::string::npos) {
                            const auto val_end = line.find('"', val_start + 1);
                            if (val_end != std::string::npos) current_account = line.substr(val_start + 1, val_end - val_start - 1);
                        }
                    }
                    if (line.find("\"PersonaName\"") != std::string::npos) {
                        const auto tab = line.find("\"PersonaName\"");
                        const auto val_start = line.find('"', tab + 13);
                        if (val_start != std::string::npos) {
                            const auto val_end = line.find('"', val_start + 1);
                            if (val_end != std::string::npos) current_persona = line.substr(val_start + 1, val_end - val_start - 1);
                        }
                    }
                    if (line.find("\"AutoLogin\"") != std::string::npos && line.find("\"1\"") != std::string::npos) {
                        autologin = true;
                    }
                }
                break;
            }
            return detected;
        };
        if(op=="local_accounts"||op=="steam_accounts"){
            return {{"local_steam_accounts", read_local_steam_accounts()}};
        }
        if(op=="import_local"){
            const auto detected = read_local_steam_accounts();
            if (detected.empty()) throw std::runtime_error("No local Steam accounts found in Steam configuration");
            Json imported = Json::array();
            std::uint32_t autologin_id = 0;
            for (const auto& item : detected) {
                const auto name = item.value("account_name", std::string{});
                if (name.empty()) continue;
                std::uint32_t acc_id = 0;
                for (const auto& acc : accounts.accounts()) {
                    if (acc.label == name) { acc_id = acc.id; break; }
                }
                if (!acc_id) {
                    acc_id = accounts.create(name);
                }
                if (item.value("auto_login", false)) autologin_id = acc_id;
                imported.push_back({{"id", acc_id}, {"account_name", name},
                                   {"persona_name", item.value("persona_name", "")},
                                   {"steam_id", item.value("steam_id", "")},
                                   {"auto_login", item.value("auto_login", false)}});
            }
            if (autologin_id && autologin_id != active_account) {
                switch_account(autologin_id);
            } else if (!active_account && !imported.empty()) {
                switch_account(imported.front().at("id").get<std::uint32_t>());
            }
            return {{"imported_local_accounts", imported}, {"active_account", active_account}};
        }
        if(op=="auth_import"||op=="import"){
            ensure_account(args);
            auto result=get_session(active_account).command("auth_import",args);
            result["account"]=active_account;return result;
        }
        if(op=="login"){
            const auto mode=args.value("mode",std::string{"qr"});if(mode!="qr"&&mode!="password")throw std::runtime_error("Login mode must be qr or password");
            if(args.contains("account")){
                const auto id=args.at("account").get<std::uint32_t>();
                if(accounts.contains(id))switch_account(id);
                else{while(accounts.accounts().size()<id)accounts.create();switch_account(id);}
            }else ensure_account(args);
            auto result=get_session(active_account).command("auth",args);
            result["account"]=active_account;return result;
        }
        if(op=="use"){
            switch_account(args.at("account").get<std::uint32_t>());return {{"active_account",active_account}};
        }
        if(op=="logout"){
            if(args.contains("account")){const auto id=args.at("account").get<std::uint32_t>();if(!active_account||active_account!=id)switch_account(id);}
            if(!active_account&&!config.auth_token_file.empty())return get_session(0).command("auth_logout",args);
            if(!active_account)throw std::runtime_error("No account selected; use login first");
            return get_session(active_account).command("auth_logout",args);
        }
        if(op=="auth"||op=="auth_input"||op=="auth_status"||op=="auth_logout")ensure_account(args);
        if(op=="connect_all"){
            std::string server=args.value("server",config.server);
            if(server.empty())throw std::runtime_error("Server endpoint must be specified (connect_all IP:PORT)");
            Json connected=Json::array();
            std::vector<std::uint32_t> target_ids;
            if(!accounts.empty()){
                for(const auto& acc:accounts.accounts())target_ids.push_back(acc.id);
            }else{
                target_ids.push_back(0);
            }
            for(auto id:target_ids){
                try{
                    auto& s=get_session(id);
                    s.command("connect",{{"server",server}});
                    connected.push_back({{"id",id},{"status","connecting"}});
                }catch(const std::exception& ex){
                    connected.push_back({{"id",id},{"error",ex.what()}});
                }
            }
            return {{"server",server},{"swarm_connect",connected}};
        }
        if(op=="disconnect_all"){
            Json disconnected=Json::array();
            for(auto& [id,sess]:sessions){
                sess->command("disconnect",args);
                disconnected.push_back(id);
            }
            return {{"swarm_disconnect",disconnected}};
        }
        if(op=="status_all"){
            Json list=Json::array();
            std::vector<std::uint32_t> ids;
            if(!accounts.empty()){
                for(const auto& acc:accounts.accounts())ids.push_back(acc.id);
            }else{
                for(const auto& [id,_]:sessions)ids.push_back(id);
                if(ids.empty())ids.push_back(0);
            }
            for(auto id:ids){
                auto& s=get_session(id);
                auto st=s.status();
                st["id"]=id;
                if(id&&accounts.contains(id))st["label"]=accounts.get(id).label;
                list.push_back(st);
            }
            return {{"swarm_status",list},{"swarm_mode",swarm_mode}};
        }
        if(op=="swarm"){
            if(args.contains("enabled"))swarm_mode=args["enabled"].get<bool>();
            else swarm_mode=!swarm_mode;
            return {{"swarm_mode",swarm_mode}};
        }
        if(op=="broadcast"){
            const auto cmd=args.value("command",std::string{});
            if(cmd.empty())throw std::runtime_error("Usage: broadcast <command>");
            const auto cmd_args=args.value("command_args",Json::object());
            Json results=Json::array();
            for(auto& [id,sess]:sessions){
                try{
                    auto res=sess->command(cmd,cmd_args);
                    results.push_back({{"id",id},{"ok",true},{"result",res}});
                }catch(const std::exception& ex){
                    results.push_back({{"id",id},{"ok",false},{"error",ex.what()}});
                }
            }
            return {{"broadcast",cmd},{"results",results}};
        }
        const bool is_gameplay_cmd=(op=="team"||op=="buy"||op=="say"||op=="say_team"||
                                    op=="aim"||op=="move"||op=="input"||op=="weapon");
        if(swarm_mode&&is_gameplay_cmd){
            Json results=Json::array();
            for(auto& [id,sess]:sessions){
                try{
                    auto res=sess->command(op,args);
                    results.push_back({{"id",id},{"ok",true},{"result",res}});
                }catch(const std::exception& ex){
                    results.push_back({{"id",id},{"ok",false},{"error",ex.what()}});
                }
            }
            return {{"broadcast",op},{"results",results}};
        }
        if(op=="connect"&&!active_account&&config.auth_token_file.empty())throw std::runtime_error("No account selected; use login first");
        if(op=="connect"){
            auto result=get_session(active_account).command(op,args);
            result["account"]=active_account;return result;
        }
        if(op=="status"){
            auto result=get_session(active_account).command(op,args);
            result["active_account"]=active_account;return result;
        }
        return get_session(active_account).command(op,args);
    };
    if(!json)std::cout<<"CS:GO Legacy 1.38.8.1 headless client. Type 'help' for commands, 'connect', or 'status'.\n";
    if(autoconnect){auto result=dispatch("connect",Json::object());emit({{"type","response"},{"ok",true},{"result",result}});}
    auto started=std::chrono::steady_clock::now();bool quit=false;
    while(!quit&&!interrupted){std::string line;for(unsigned count=0;!quit&&count<64&&reader.pop(line);++count){if(line.empty())continue;Json id=nullptr;
        try{Json request; if(!json&&line.rfind(std::string("\x01")+"AUTH_INPUT\t",0)==0){const auto rest=line.substr(12);const auto tab=rest.find('\t');if(tab==std::string::npos)throw std::runtime_error("Hidden authentication input is malformed");request={{"op","auth_input"},{"args",{{"prompt_id",rest.substr(0,tab)},{"value",rest.substr(tab+1)}}}};}else request=json?Json::parse(line):hc::parse_interactive(line);if(!request.is_object())throw std::runtime_error("Request must be an object");id=request.value("id",Json(nullptr));auto op=request.at("op").get<std::string>();auto args=request.value("args",Json::object());auto result=dispatch(op,args);emit({{"type","response"},{"id",id},{"ok",true},{"result",result}});if(op=="quit")quit=true;}
        catch(const std::exception&e){emit({{"type","response"},{"id",id},{"ok",false},{"error",{{"message",e.what()}}}});}
    }
        std::vector<hc::Session*> poll_ptrs;
        poll_ptrs.reserve(sessions.size());
        for(auto& [id,s]:sessions)poll_ptrs.push_back(s.get());
        for(auto* s:poll_ptrs)s->poll();
        if(run_seconds&&std::chrono::steady_clock::now()-started>std::chrono::seconds(run_seconds)){emit({{"type","run_complete"},{"status",get_session(active_account).status()}});quit=true;}
        if(reader.eof()&&!run_seconds)quit=true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    for(auto& [id,sess]:sessions)sess->disconnect("client exit");
    return 0;
}catch(const std::exception&e){std::cerr<<"headless-csgo: "<<e.what()<<'\n';return 1;}}
