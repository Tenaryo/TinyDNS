#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

inline auto parse_labels(std::span<const std::byte> full_msg,
                         size_t offset) -> std::pair<std::vector<std::string>, size_t> {
    std::vector<std::string> labels;
    std::unordered_set<size_t> visited;
    size_t local_consumed = 0;
    bool followed_pointer = false;
    size_t jump_offset = offset;

    while (jump_offset < full_msg.size()) {
        uint8_t b = static_cast<uint8_t>(full_msg[jump_offset]);

        if (b == 0) {
            if (!followed_pointer) {
                local_consumed += 1;
            }
            break;
        }

        if ((b & 0xC0) == 0xC0) {
            if (!followed_pointer) {
                local_consumed += 2;
                followed_pointer = true;
            }
            size_t ptr = (static_cast<size_t>(b & 0x3F) << 8) |
                         static_cast<size_t>(full_msg[jump_offset + 1]);
            if (!visited.insert(ptr).second)
                break;
            jump_offset = ptr;
            continue;
        }

        ++jump_offset;
        labels.emplace_back(reinterpret_cast<const char*>(&full_msg[jump_offset]), b);
        jump_offset += b;
        if (!followed_pointer) {
            local_consumed += 1 + b;
        }
    }

    return {labels, local_consumed};
}
