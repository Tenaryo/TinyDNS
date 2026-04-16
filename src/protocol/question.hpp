#pragma once

#include "label.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

struct DnsQuestion {
    std::vector<std::string> labels;
    uint16_t type{};
    uint16_t qclass{};

    static auto parse(std::span<const std::byte> full_msg,
                      size_t offset) -> std::pair<DnsQuestion, size_t> {
        DnsQuestion q;
        auto [labels, consumed] = parse_labels(full_msg, offset);
        q.labels = std::move(labels);

        size_t pos = offset + consumed;
        auto get_u16 = [&]() -> uint16_t {
            auto val = static_cast<uint16_t>((static_cast<uint16_t>(full_msg[pos]) << 8) |
                                             static_cast<uint16_t>(full_msg[pos + 1]));
            pos += 2;
            return val;
        };
        q.type = get_u16();
        q.qclass = get_u16();

        return {q, consumed + 4};
    }

    auto serialize() const -> std::vector<std::byte> {
        std::vector<std::byte> buf;
        for (const auto& label : labels) {
            buf.push_back(static_cast<std::byte>(label.size()));
            for (char c : label) {
                buf.push_back(static_cast<std::byte>(c));
            }
        }
        buf.push_back(std::byte{0});

        auto put_u16 = [&buf](uint16_t val) {
            buf.push_back(static_cast<std::byte>(val >> 8));
            buf.push_back(static_cast<std::byte>(val & 0xFF));
        };
        put_u16(type);
        put_u16(qclass);

        return buf;
    }
};
