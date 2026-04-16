#pragma once

#include "label.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

struct DnsResourceRecord {
    std::vector<std::string> name;
    uint16_t type{};
    uint16_t cls{};
    uint32_t ttl{};
    std::vector<std::byte> rdata;

    static auto parse(std::span<const std::byte> full_msg,
                      size_t offset) -> std::pair<DnsResourceRecord, size_t> {
        DnsResourceRecord rr;
        auto [labels, consumed] = parse_labels(full_msg, offset);
        rr.name = std::move(labels);

        size_t pos = offset + consumed;
        auto get_u16 = [&]() -> uint16_t {
            auto val = static_cast<uint16_t>((static_cast<uint16_t>(full_msg[pos]) << 8) |
                                             static_cast<uint16_t>(full_msg[pos + 1]));
            pos += 2;
            return val;
        };

        rr.type = get_u16();
        rr.cls = get_u16();

        auto get_u32 = [&]() -> uint32_t {
            auto val = static_cast<uint32_t>((static_cast<uint32_t>(full_msg[pos]) << 24) |
                                             (static_cast<uint32_t>(full_msg[pos + 1]) << 16) |
                                             (static_cast<uint32_t>(full_msg[pos + 2]) << 8) |
                                             static_cast<uint32_t>(full_msg[pos + 3]));
            pos += 4;
            return val;
        };
        rr.ttl = get_u32();

        uint16_t rdlength = get_u16();
        rr.rdata.assign(full_msg.begin() + static_cast<ptrdiff_t>(pos),
                        full_msg.begin() + static_cast<ptrdiff_t>(pos + rdlength));
        pos += rdlength;

        return {rr, pos - offset};
    }

    auto serialize() const -> std::vector<std::byte> {
        std::vector<std::byte> buf;
        for (const auto& label : name) {
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
        put_u16(cls);

        auto put_u32 = [&buf](uint32_t val) {
            buf.push_back(static_cast<std::byte>((val >> 24) & 0xFF));
            buf.push_back(static_cast<std::byte>((val >> 16) & 0xFF));
            buf.push_back(static_cast<std::byte>((val >> 8) & 0xFF));
            buf.push_back(static_cast<std::byte>(val & 0xFF));
        };
        put_u32(ttl);
        put_u16(static_cast<uint16_t>(rdata.size()));
        buf.insert(buf.end(), rdata.begin(), rdata.end());

        return buf;
    }
};
