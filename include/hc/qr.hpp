#pragma once

#include <string>
#include <string_view>

namespace hc {

// Render a Steam authentication URL as a compact Unicode QR matrix for an
// interactive terminal. The URL remains available separately in auth_qr JSON.
std::string render_qr(std::string_view url);

} // namespace hc
