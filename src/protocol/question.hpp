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
        if (pos + 4 > full_msg.size())
            throw std::runtime_error("DNS question truncated");

        q.type = read_u16(full_msg, pos);
        q.qclass = read_u16(full_msg, pos + 2);

        return {q, consumed + 4};
    }

    auto serialize() const -> std::vector<std::byte> {
        size_t labels_size = std::accumulate(
            labels.begin(), labels.end(), size_t{1}, [](size_t acc, const std::string& s) {
                return acc + 1 + s.size();
            });
        std::vector<std::byte> buf;
        buf.reserve(labels_size + 4);

        append_labels(buf, labels);
        append_u16(buf, type);
        append_u16(buf, qclass);

        return buf;
    }
};
