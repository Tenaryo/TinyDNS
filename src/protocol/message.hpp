#pragma once

#include "header.hpp"

#include <cstddef>
#include <span>
#include <vector>

struct DnsMessage {
    DnsHeader header{};

    static auto parse(std::span<const std::byte> data) -> DnsMessage {
        return DnsMessage{.header = DnsHeader::parse(data)};
    }

    auto serialize() const -> std::vector<std::byte> {
        auto hdr = header.serialize();
        return {hdr.begin(), hdr.end()};
    }
};
