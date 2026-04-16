#pragma once

#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

struct ResolverAddr {
    std::string ip;
    uint16_t port{};
};

inline auto parse_resolver(std::string_view addr_str) -> std::optional<ResolverAddr> {
    auto colon = addr_str.rfind(':');
    if (colon == std::string_view::npos)
        return std::nullopt;

    auto ip_part = addr_str.substr(0, colon);
    auto port_part = addr_str.substr(colon + 1);

    if (ip_part.empty() || port_part.empty())
        return std::nullopt;

    uint16_t port = 0;
    auto result = std::from_chars(port_part.data(), port_part.data() + port_part.size(), port);
    if (result.ec != std::errc{} || port == 0)
        return std::nullopt;

    return ResolverAddr{std::string{ip_part}, port};
}
