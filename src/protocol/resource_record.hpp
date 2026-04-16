#pragma once

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

    static auto parse(std::span<const std::byte> data) -> std::pair<DnsResourceRecord, size_t>;
    auto serialize() const -> std::vector<std::byte>;
};
