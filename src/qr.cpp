#include "hc/qr.hpp"

#include "qrcodegen/qrcodegen.hpp"

#include <stdexcept>

namespace hc {

std::string render_qr(std::string_view url) {
    const std::string text(url);
    if (text.empty()) throw std::runtime_error("Cannot render an empty QR challenge");
    const auto qr = qrcodegen::QrCode::encodeText(text.c_str(), qrcodegen::QrCode::Ecc::MEDIUM);
    constexpr int border = 2;
    std::string result;
    result.reserve(static_cast<std::size_t>((qr.getSize() + border * 2) * (qr.getSize() + border * 2) / 2));
    for (int y = -border; y < qr.getSize() + border; y += 2) {
        for (int x = -border; x < qr.getSize() + border; ++x) {
            const bool top = x >= -border && x < qr.getSize() + border &&
                             y >= -border && y < qr.getSize() + border &&
                             (x < 0 || y < 0 || x >= qr.getSize() || y >= qr.getSize() || qr.getModule(x, y));
            const int bottom_y = y + 1;
            const bool bottom = x >= -border && x < qr.getSize() + border &&
                                bottom_y >= -border && bottom_y < qr.getSize() + border &&
                                (x < 0 || bottom_y < 0 || x >= qr.getSize() || bottom_y >= qr.getSize() || qr.getModule(x, bottom_y));
            if (top && bottom) result += "\xE2\x96\x88";       // full block
            else if (top) result += "\xE2\x96\x80";           // upper half block
            else if (bottom) result += "\xE2\x96\x84";        // lower half block
            else result.push_back(' ');
        }
        result.push_back('\n');
    }
    return result;
}

std::string render_qr_ascii(std::string_view url) {
    const std::string text(url);
    if (text.empty()) throw std::runtime_error("Cannot render an empty QR challenge");
    const auto qr = qrcodegen::QrCode::encodeText(text.c_str(), qrcodegen::QrCode::Ecc::MEDIUM);
    constexpr int border = 2;
    std::string result;
    result.reserve(static_cast<std::size_t>((qr.getSize() + border * 2) * (qr.getSize() + border * 2) * 2));
    for (int y = -border; y < qr.getSize() + border; ++y) {
        for (int x = -border; x < qr.getSize() + border; ++x) {
            const bool dark = x < 0 || y < 0 || x >= qr.getSize() || y >= qr.getSize() || qr.getModule(x, y);
            result += dark ? "##" : "  ";
        }
        result.push_back('\n');
    }
    return result;
}

std::string render_qr_squares(std::string_view url) {
    const std::string text(url);
    if (text.empty()) throw std::runtime_error("Cannot render an empty QR challenge");
    const auto qr = qrcodegen::QrCode::encodeText(text.c_str(), qrcodegen::QrCode::Ecc::MEDIUM);
    constexpr int border = 2;
    std::string result;
    result.reserve(static_cast<std::size_t>((qr.getSize() + border * 2) * (qr.getSize() + border * 2) * 3));
    for (int y = -border; y < qr.getSize() + border; ++y) {
        for (int x = -border; x < qr.getSize() + border; ++x) {
            const bool dark = x < 0 || y < 0 || x >= qr.getSize() || y >= qr.getSize() || qr.getModule(x, y);
            result += dark ? "\xE2\xAC\x9B" : "\xE2\xAC\x9C"; // ⬛ / ⬜
        }
        result.push_back('\n');
    }
    return result;
}

} // namespace hc
