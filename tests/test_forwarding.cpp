#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "protocol/message.hpp"
#include "resolver.hpp"
#include "server.hpp"

auto test_parse_resolver_valid() -> bool {
    auto result = parse_resolver("1.2.3.4:5353");
    if (!result.has_value()) {
        std::cerr << "parse_resolver: expected valid result" << std::endl;
        return false;
    }
    if (result->ip != "1.2.3.4") {
        std::cerr << "parse_resolver: ip expected '1.2.3.4', got '" << result->ip << "'"
                  << std::endl;
        return false;
    }
    if (result->port != 5353) {
        std::cerr << "parse_resolver: port expected 5353, got " << result->port << std::endl;
        return false;
    }
    return true;
}

auto test_parse_resolver_absent() -> bool {
    auto result = parse_resolver("");
    if (result.has_value()) {
        std::cerr << "parse_resolver: expected nullopt for empty string" << std::endl;
        return false;
    }
    return true;
}

static auto make_query_with_domain(uint16_t id, std::string_view domain) -> std::vector<std::byte> {
    std::vector<std::byte> buf(12);
    buf[0] = static_cast<std::byte>(id >> 8);
    buf[1] = static_cast<std::byte>(id & 0xFF);
    buf[2] = std::byte{0x01};
    buf[3] = std::byte{0x00};
    buf[4] = std::byte{0x00};
    buf[5] = std::byte{0x01};
    buf[6] = std::byte{0x00};
    buf[7] = std::byte{0x00};
    buf[8] = std::byte{0x00};
    buf[9] = std::byte{0x00};
    buf[10] = std::byte{0x00};
    buf[11] = std::byte{0x00};

    size_t start = 0;
    while (start < domain.size()) {
        auto dot = domain.find('.', start);
        auto label = (dot == std::string_view::npos) ? domain.substr(start)
                                                     : domain.substr(start, dot - start);
        buf.push_back(static_cast<std::byte>(label.size()));
        for (auto c : label)
            buf.push_back(static_cast<std::byte>(c));
        if (dot == std::string_view::npos)
            break;
        start = dot + 1;
    }
    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0x01});
    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0x01});
    return buf;
}

static auto make_resolver_response(uint16_t id,
                                   std::string_view domain,
                                   uint32_t ttl,
                                   std::array<uint8_t, 4> ip) -> std::vector<std::byte> {
    auto buf = make_query_with_domain(id, domain);
    buf[2] = static_cast<std::byte>(0x80);
    buf[6] = std::byte{0x00};
    buf[7] = std::byte{0x01};

    size_t start = 0;
    while (start < domain.size()) {
        auto dot = domain.find('.', start);
        auto label = (dot == std::string_view::npos) ? domain.substr(start)
                                                     : domain.substr(start, dot - start);
        buf.push_back(static_cast<std::byte>(label.size()));
        for (auto c : label)
            buf.push_back(static_cast<std::byte>(c));
        if (dot == std::string_view::npos)
            break;
        start = dot + 1;
    }
    buf.push_back(std::byte{0x00});

    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0x01});
    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0x01});
    buf.push_back(static_cast<std::byte>((ttl >> 24) & 0xFF));
    buf.push_back(static_cast<std::byte>((ttl >> 16) & 0xFF));
    buf.push_back(static_cast<std::byte>((ttl >> 8) & 0xFF));
    buf.push_back(static_cast<std::byte>(ttl & 0xFF));
    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0x04});
    for (auto b : ip)
        buf.push_back(static_cast<std::byte>(b));
    return buf;
}

auto test_forward_single_query() -> bool {
    auto query = make_query_with_domain(0x1234, "example.com");
    auto resolver_resp = make_resolver_response(0x1234, "example.com", 300, {10, 0, 0, 1});
    std::vector<std::vector<std::byte>> responses = {resolver_resp};
    auto resp = build_forward_response(query, responses);
    auto msg = DnsMessage::parse(resp);

    if (msg.header.id != 0x1234) {
        std::cerr << "forward_single: id mismatch" << std::endl;
        return false;
    }
    if (msg.header.qr != true) {
        std::cerr << "forward_single: qr expected 1" << std::endl;
        return false;
    }
    if (msg.header.qdcount != 1) {
        std::cerr << "forward_single: qdcount expected 1, got " << msg.header.qdcount << std::endl;
        return false;
    }
    if (msg.header.ancount != 1) {
        std::cerr << "forward_single: ancount expected 1, got " << msg.header.ancount << std::endl;
        return false;
    }
    if (msg.questions.size() != 1) {
        std::cerr << "forward_single: expected 1 question" << std::endl;
        return false;
    }
    if (msg.questions[0].labels[0] != "example" || msg.questions[0].labels[1] != "com") {
        std::cerr << "forward_single: question labels mismatch" << std::endl;
        return false;
    }
    if (msg.answers.size() != 1) {
        std::cerr << "forward_single: expected 1 answer, got " << msg.answers.size() << std::endl;
        return false;
    }
    if (msg.answers[0].name[0] != "example" || msg.answers[0].name[1] != "com") {
        std::cerr << "forward_single: answer name mismatch" << std::endl;
        return false;
    }
    if (msg.answers[0].ttl != 300) {
        std::cerr << "forward_single: ttl expected 300, got " << msg.answers[0].ttl << std::endl;
        return false;
    }
    if (msg.answers[0].rdata.size() != 4 || static_cast<uint8_t>(msg.answers[0].rdata[0]) != 10 ||
        static_cast<uint8_t>(msg.answers[0].rdata[1]) != 0 ||
        static_cast<uint8_t>(msg.answers[0].rdata[2]) != 0 ||
        static_cast<uint8_t>(msg.answers[0].rdata[3]) != 1) {
        std::cerr << "forward_single: rdata mismatch (expected 10.0.0.1)" << std::endl;
        return false;
    }
    return true;
}

auto test_forward_multiple_queries() -> bool {
    std::vector<std::byte> query;
    query.push_back(std::byte{0xAA});
    query.push_back(std::byte{0xBB});
    query.push_back(std::byte{0x01});
    query.push_back(std::byte{0x00});
    query.push_back(std::byte{0x00});
    query.push_back(std::byte{0x02});
    query.push_back(std::byte{0x00});
    query.push_back(std::byte{0x00});
    query.push_back(std::byte{0x00});
    query.push_back(std::byte{0x00});
    query.push_back(std::byte{0x00});
    query.push_back(std::byte{0x00});

    auto q1 = make_query_with_domain(0, "codecrafters.io");
    auto q2 = make_query_with_domain(0, "example.com");
    query.insert(query.end(), q1.begin() + 12, q1.end());
    query.insert(query.end(), q2.begin() + 12, q2.end());

    auto rr1 = make_resolver_response(0, "codecrafters.io", 60, {1, 2, 3, 4});
    auto rr2 = make_resolver_response(0, "example.com", 120, {5, 6, 7, 8});
    std::vector<std::vector<std::byte>> responses = {rr1, rr2};

    auto resp = build_forward_response(query, responses);
    auto msg = DnsMessage::parse(resp);

    if (msg.header.id != 0xAABB) {
        std::cerr << "forward_multi: id mismatch" << std::endl;
        return false;
    }
    if (msg.header.qr != true) {
        std::cerr << "forward_multi: qr expected 1" << std::endl;
        return false;
    }
    if (msg.header.qdcount != 2) {
        std::cerr << "forward_multi: qdcount expected 2, got " << msg.header.qdcount << std::endl;
        return false;
    }
    if (msg.header.ancount != 2) {
        std::cerr << "forward_multi: ancount expected 2, got " << msg.header.ancount << std::endl;
        return false;
    }
    if (msg.questions.size() != 2) {
        std::cerr << "forward_multi: expected 2 questions, got " << msg.questions.size()
                  << std::endl;
        return false;
    }
    if (msg.answers.size() != 2) {
        std::cerr << "forward_multi: expected 2 answers, got " << msg.answers.size() << std::endl;
        return false;
    }
    if (msg.answers[0].name[0] != "codecrafters" || msg.answers[0].name[1] != "io") {
        std::cerr << "forward_multi: answer1 name mismatch" << std::endl;
        return false;
    }
    if (msg.answers[0].ttl != 60) {
        std::cerr << "forward_multi: answer1 ttl expected 60" << std::endl;
        return false;
    }
    if (msg.answers[1].name[0] != "example" || msg.answers[1].name[1] != "com") {
        std::cerr << "forward_multi: answer2 name mismatch" << std::endl;
        return false;
    }
    if (msg.answers[1].ttl != 120) {
        std::cerr << "forward_multi: answer2 ttl expected 120" << std::endl;
        return false;
    }
    return true;
}

int main() {
    bool all_passed = true;

    if (!test_parse_resolver_valid()) {
        std::cerr << "FAIL: test_parse_resolver_valid" << std::endl;
        all_passed = false;
    } else {
        std::cout << "PASS: test_parse_resolver_valid" << std::endl;
    }

    if (!test_parse_resolver_absent()) {
        std::cerr << "FAIL: test_parse_resolver_absent" << std::endl;
        all_passed = false;
    } else {
        std::cout << "PASS: test_parse_resolver_absent" << std::endl;
    }

    if (!test_forward_single_query()) {
        std::cerr << "FAIL: test_forward_single_query" << std::endl;
        all_passed = false;
    } else {
        std::cout << "PASS: test_forward_single_query" << std::endl;
    }

    if (!test_forward_multiple_queries()) {
        std::cerr << "FAIL: test_forward_multiple_queries" << std::endl;
        all_passed = false;
    } else {
        std::cout << "PASS: test_forward_multiple_queries" << std::endl;
    }

    return all_passed ? 0 : 1;
}
