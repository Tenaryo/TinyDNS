#pragma once

#include "header.hpp"
#include "question.hpp"
#include "resource_record.hpp"

#include <cstddef>
#include <span>
#include <vector>

struct DnsMessage {
    DnsHeader header{};
    std::vector<DnsQuestion> questions;
    std::vector<DnsResourceRecord> answers;

    static auto parse(std::span<const std::byte> data) -> DnsMessage;
    auto serialize() const -> std::vector<std::byte>;
};
