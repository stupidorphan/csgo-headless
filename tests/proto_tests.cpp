#include "hc/proto.hpp"
#include <iostream>
#include <stdexcept>
static void check(bool b){if(!b)throw std::runtime_error("protobuf assertion failed");}
int main(){try{
  hc::ProtoWriter inner;inner.string(1,"nested");
  hc::ProtoWriter w;w.u32(1,300).i32(2,-1).fixed32(3,0xdeadbeef).fixed64(4,0x123456789abcdef0).float32(5,1.25f).string(6,"hello").message(7,inner).u32(1,400);
  hc::Proto p(w.data());check(p.get_u32(1)==400);check(p.fields(1).size()==2);check(p.get_i32(2)==-1);check(p.get_u32(3)==0xdeadbeef);check(p.get_u64(4)==0x123456789abcdef0);check(p.get_float(5)==1.25f);check(p.get_string(6)=="hello");check(p.get_messages(7).at(0).get_string(1)=="nested");check(!p.has(8));
  for(hc::Bytes b:std::vector<hc::Bytes>{{0},{8,128},{18,5,1},{13,1},{8,255,255,255,255,255,255,255,255,255,2}}){bool failed=false;try{hc::Proto bad(b);}catch(const hc::WireError&){failed=true;}check(failed);}
  std::cout<<"protobuf codec tests passed\n";return 0;
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}
