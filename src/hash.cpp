#include <windows.h>
#include <bcrypt.h>
#include "hc/hash.hpp"
#include <array>
#include <limits>
#include <stdexcept>
namespace hc {
std::string sha256(std::span<const std::uint8_t> data) {
    if(data.size()>std::numeric_limits<ULONG>::max())throw std::runtime_error("SHA256 input too large");
    BCRYPT_ALG_HANDLE provider{};
    if(BCryptOpenAlgorithmProvider(&provider,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0)throw std::runtime_error("SHA256 provider unavailable");
    std::array<UCHAR,32> digest{};
    auto code=BCryptHash(provider,nullptr,0,const_cast<PUCHAR>(data.data()),ULONG(data.size()),digest.data(),ULONG(digest.size()));
    BCryptCloseAlgorithmProvider(provider,0);
    if(code<0)throw std::runtime_error("SHA256 failed");
    std::string result;constexpr char hex[]="0123456789abcdef";
    for(auto byte:digest){result+=hex[byte>>4];result+=hex[byte&15];}
    return result;
}
}
