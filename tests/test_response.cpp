#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

#include "protocol/header.hpp"
#include "server.hpp"

auto make_query(uint16_t id, uint8_t opcode, bool rd) -> std::vector<std::byte> {
    std::vector<std::byte> buf(12);

    buf[0] = static_cast<std::byte>(id >> 8);
    buf[1] = static_cast<std::byte>(id & 0xFF);

    uint8_t flags2 = (static_cast<uint8_t>(opcode & 0xF) << 3) | (static_cast<uint8_t>(rd) & 0x1);
    buf[2] = static_cast<std::byte>(flags2);
    buf[3] = std::byte{0x00};

    buf[4] = std::byte{0x00};
    buf[5] = std::byte{0x01};
    buf[6] = std::byte{0x00};
    buf[7] = std::byte{0x00};
    buf[8] = std::byte{0x00};
    buf[9] = std::byte{0x00};
    buf[10] = std::byte{0x00};
    buf[11] = std::byte{0x00};

    for (auto c : std::string{"\x0ccodecrafters\x02io\x00"}) {
        buf.push_back(static_cast<std::byte>(c));
    }
    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0x01});
    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0x01});

    return buf;
}

auto test_standard_query_response_header() -> bool {
    auto query = make_query(0x1234, 0, true);
    auto resp = create_response(query);
    auto hdr = DnsHeader::parse(resp);

    if (hdr.id != 0x1234) {
        std::cerr << "id mismatch" << std::endl;
        return false;
    }
    if (hdr.qr != true) {
        std::cerr << "qr expected 1" << std::endl;
        return false;
    }
    if (hdr.opcode != 0) {
        std::cerr << "opcode expected 0" << std::endl;
        return false;
    }
    if (hdr.aa != false) {
        std::cerr << "aa expected 0" << std::endl;
        return false;
    }
    if (hdr.tc != false) {
        std::cerr << "tc expected 0" << std::endl;
        return false;
    }
    if (hdr.rd != true) {
        std::cerr << "rd expected 1 (echo)" << std::endl;
        return false;
    }
    if (hdr.ra != false) {
        std::cerr << "ra expected 0" << std::endl;
        return false;
    }
    if (hdr.z != 0) {
        std::cerr << "z expected 0" << std::endl;
        return false;
    }
    if (hdr.rcode != 0) {
        std::cerr << "rcode expected 0" << std::endl;
        return false;
    }
    return true;
}

auto test_response_id_echo() -> bool {
    auto query = make_query(0xABCD, 0, false);
    auto resp = create_response(query);
    auto hdr = DnsHeader::parse(resp);

    if (hdr.id != 0xABCD) {
        std::cerr << "id echo: expected 0xABCD, got " << std::hex << hdr.id << std::endl;
        return false;
    }
    return true;
}

int main() {
    bool all_passed = true;

    if (!test_standard_query_response_header()) {
        std::cerr << "FAIL: test_standard_query_response_header" << std::endl;
        all_passed = false;
    } else {
        std::cout << "PASS: test_standard_query_response_header" << std::endl;
    }

    if (!test_response_id_echo()) {
        std::cerr << "FAIL: test_response_id_echo" << std::endl;
        all_passed = false;
    } else {
        std::cout << "PASS: test_response_id_echo" << std::endl;
    }

    return all_passed ? 0 : 1;
}
