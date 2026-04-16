#pragma once

#include "header.hpp"
#include "question.hpp"

#include <cstddef>
#include <span>
#include <vector>

struct DnsMessage {
    DnsHeader header{};
    std::vector<DnsQuestion> questions;

    static auto parse(std::span<const std::byte> data) -> DnsMessage {
        DnsMessage msg{};
        msg.header = DnsHeader::parse(data);
        size_t offset = 12;
        for (uint16_t i = 0; i < msg.header.qdcount; ++i) {
            auto [q, consumed] = DnsQuestion::parse(data.subspan(offset));
            msg.questions.push_back(std::move(q));
            offset += consumed;
        }
        return msg;
    }

    auto serialize() const -> std::vector<std::byte> {
        auto hdr = header.serialize();
        std::vector<std::byte> buf{hdr.begin(), hdr.end()};
        for (const auto& q : questions) {
            auto qbuf = q.serialize();
            buf.insert(buf.end(), qbuf.begin(), qbuf.end());
        }
        return buf;
    }
};
