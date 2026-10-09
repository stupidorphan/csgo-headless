#pragma once

#include <string>
#include <string_view>

namespace hc {

// Render a Steam authentication URL as compact Unicode and ASCII-safe QR
// matrices. The URL remains available separately in auth_qr JSON.
std::string render_qr(std::string_view url);
std::string render_qr_ascii(std::string_view url);
std::string render_qr_squares(std::string_view url);

} // namespace hc
