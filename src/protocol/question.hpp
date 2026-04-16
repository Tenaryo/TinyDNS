#pragma once

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

    static auto parse(std::span<const std::byte> data)
        -> std::pair<DnsQuestion, size_t> {
        DnsQuestion q;
        size_t offset = 0;

        while (offset < data.size()) {
            uint8_t len = static_cast<uint8_t>(data[offset]);
            ++offset;
            if (len == 0) break;
            q.labels.emplace_back(
                reinterpret_cast<const char*>(&data[offset]), len);
            offset += len;
        }

        auto get_u16 = [&data, &offset]() -> uint16_t {
            auto val = static_cast<uint16_t>(
                (static_cast<uint16_t>(data[offset]) << 8) |
                static_cast<uint16_t>(data[offset + 1]));
            offset += 2;
            return val;
        };
        q.type = get_u16();
        q.qclass = get_u16();

        return {q, offset};
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
