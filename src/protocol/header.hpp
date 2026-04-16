#pragma once

#include "codec.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>

struct DnsHeader {
    uint16_t id{};
    bool qr{};
    uint8_t opcode{};
    bool aa{};
    bool tc{};
    bool rd{};
    bool ra{};
    uint8_t z{};
    uint8_t rcode{};
    uint16_t qdcount{};
    uint16_t ancount{};
    uint16_t nscount{};
    uint16_t arcount{};

    static auto parse(std::span<const std::byte> data) -> DnsHeader {
        if (data.size() < 12)
            throw std::runtime_error("DNS header too short");

        DnsHeader hdr{};
        hdr.id = read_u16(data, 0);

        uint8_t byte2 = static_cast<uint8_t>(data[2]);
        uint8_t byte3 = static_cast<uint8_t>(data[3]);

        hdr.qr = (byte2 >> 7) & 0x1;
        hdr.opcode = (byte2 >> 3) & 0xF;
        hdr.aa = (byte2 >> 2) & 0x1;
        hdr.tc = (byte2 >> 1) & 0x1;
        hdr.rd = byte2 & 0x1;

        hdr.ra = (byte3 >> 7) & 0x1;
        hdr.z = (byte3 >> 4) & 0x7;
        hdr.rcode = byte3 & 0xF;

        hdr.qdcount = read_u16(data, 4);
        hdr.ancount = read_u16(data, 6);
        hdr.nscount = read_u16(data, 8);
        hdr.arcount = read_u16(data, 10);

        return hdr;
    }

    auto serialize() const -> std::array<std::byte, 12> {
        std::array<std::byte, 12> buf{};

        buf[0] = static_cast<std::byte>(id >> 8);
        buf[1] = static_cast<std::byte>(id & 0xFF);

        buf[2] = static_cast<std::byte>((static_cast<uint8_t>(qr) << 7) |
                                        (static_cast<uint8_t>(opcode) << 3) |
                                        (static_cast<uint8_t>(aa) << 2) |
                                        (static_cast<uint8_t>(tc) << 1) | static_cast<uint8_t>(rd));

        buf[3] =
            static_cast<std::byte>((static_cast<uint8_t>(ra) << 7) |
                                   (static_cast<uint8_t>(z) << 4) | static_cast<uint8_t>(rcode));

        auto put_u16 = [&buf](size_t idx, uint16_t val) {
            buf[idx] = static_cast<std::byte>(val >> 8);
            buf[idx + 1] = static_cast<std::byte>(val & 0xFF);
        };
        put_u16(4, qdcount);
        put_u16(6, ancount);
        put_u16(8, nscount);
        put_u16(10, arcount);

        return buf;
    }
};
