#pragma once

#include "codec.hpp"
#include "label.hpp"

#include <cstddef>
#include <cstdint>
#include <numeric>
#include <span>
#include <stdexcept>
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
        if (pos + 10 > full_msg.size())
            throw std::runtime_error("DNS resource record truncated");

        rr.type = read_u16(full_msg, pos);
        rr.cls = read_u16(full_msg, pos + 2);
        rr.ttl = read_u32(full_msg, pos + 4);
        uint16_t rdlength = read_u16(full_msg, pos + 8);

        pos += 10;
        if (pos + rdlength > full_msg.size())
            throw std::runtime_error("DNS resource record rdata truncated");

        rr.rdata.assign(full_msg.begin() + static_cast<ptrdiff_t>(pos),
                        full_msg.begin() + static_cast<ptrdiff_t>(pos + rdlength));
        pos += rdlength;

        return {rr, pos - offset};
    }

    auto serialize() const -> std::vector<std::byte> {
        size_t name_size = std::accumulate(
            name.begin(), name.end(), size_t{1}, [](size_t acc, const std::string& s) {
                return acc + 1 + s.size();
            });
        std::vector<std::byte> buf;
        buf.reserve(name_size + 10 + rdata.size());

        append_labels(buf, name);
        append_u16(buf, type);
        append_u16(buf, cls);
        append_u32(buf, ttl);
        append_u16(buf, static_cast<uint16_t>(rdata.size()));
        buf.insert(buf.end(), rdata.begin(), rdata.end());

        return buf;
    }
};
