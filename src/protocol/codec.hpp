#pragma once

#include <cstddef>
#include <cstdint>
#include <ranges>
#include <span>
#include <string>
#include <vector>

inline auto read_u16(std::span<const std::byte> data, size_t offset) -> uint16_t {
    return static_cast<uint16_t>((static_cast<uint16_t>(data[offset]) << 8) |
                                 static_cast<uint16_t>(data[offset + 1]));
}

inline auto read_u32(std::span<const std::byte> data, size_t offset) -> uint32_t {
    return static_cast<uint32_t>((static_cast<uint32_t>(data[offset]) << 24) |
                                 (static_cast<uint32_t>(data[offset + 1]) << 16) |
                                 (static_cast<uint32_t>(data[offset + 2]) << 8) |
                                 static_cast<uint32_t>(data[offset + 3]));
}

inline void append_u16(std::vector<std::byte>& buf, uint16_t val) {
    buf.push_back(static_cast<std::byte>(val >> 8));
    buf.push_back(static_cast<std::byte>(val & 0xFF));
}

inline void append_u32(std::vector<std::byte>& buf, uint32_t val) {
    buf.push_back(static_cast<std::byte>((val >> 24) & 0xFF));
    buf.push_back(static_cast<std::byte>((val >> 16) & 0xFF));
    buf.push_back(static_cast<std::byte>((val >> 8) & 0xFF));
    buf.push_back(static_cast<std::byte>(val & 0xFF));
}

inline void append_labels(std::vector<std::byte>& buf, const std::ranges::range auto& labels) {
    for (const auto& label : labels) {
        buf.push_back(static_cast<std::byte>(label.size()));
        for (char c : label)
            buf.push_back(static_cast<std::byte>(c));
    }
    buf.push_back(std::byte{0});
}
