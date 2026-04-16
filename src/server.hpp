#pragma once

#include "protocol/message.hpp"
#include "resolver.hpp"

#include <arpa/inet.h>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <optional>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

auto create_response(std::span<const std::byte> request) -> std::vector<std::byte> {
    auto msg = DnsMessage::parse(request);

    msg.header.qr = true;
    msg.header.aa = false;
    msg.header.tc = false;
    msg.header.ra = false;
    msg.header.z = 0;
    msg.header.rcode = (msg.header.opcode == 0) ? 0 : 4;
    msg.header.ancount = static_cast<uint16_t>(msg.questions.size());

    for (const auto& q : msg.questions) {
        DnsResourceRecord answer{};
        answer.name = q.labels;
        answer.type = 1;
        answer.cls = 1;
        answer.ttl = 60;
        answer.rdata = {std::byte{0x08}, std::byte{0x08}, std::byte{0x08}, std::byte{0x08}};
        msg.answers.push_back(std::move(answer));
    }

    return msg.serialize();
}

auto build_forward_response(std::span<const std::byte> query,
                            std::span<const std::vector<std::byte>> resolver_responses)
    -> std::vector<std::byte> {
    auto msg = DnsMessage::parse(query);

    msg.header.qr = true;
    msg.header.aa = false;
    msg.header.tc = false;
    msg.header.ra = false;
    msg.header.z = 0;
    msg.header.rcode = (msg.header.opcode == 0) ? 0 : 4;
    msg.header.ancount = 0;
    msg.answers.clear();

    for (const auto& resp_bytes : resolver_responses) {
        auto resp_msg = DnsMessage::parse(resp_bytes);
        for (auto& rr : resp_msg.answers) {
            msg.answers.push_back(std::move(rr));
            ++msg.header.ancount;
        }
    }

    return msg.serialize();
}

class DnsServer {
    int sockfd_{-1};
    int resolver_sock_{-1};
    uint16_t port_;
    std::optional<ResolverAddr> resolver_;
  public:
    explicit DnsServer(uint16_t port, std::optional<ResolverAddr> resolver = std::nullopt)
        : port_{port}, resolver_{std::move(resolver)} {}

    ~DnsServer() {
        if (resolver_sock_ != -1)
            close(resolver_sock_);
        if (sockfd_ != -1)
            close(sockfd_);
    }

    DnsServer(const DnsServer&) = delete;
    auto operator=(const DnsServer&) -> DnsServer& = delete;
    DnsServer(DnsServer&& o) noexcept
        : sockfd_{o.sockfd_}, resolver_sock_{o.resolver_sock_}, port_{o.port_},
          resolver_{std::move(o.resolver_)} {
        o.sockfd_ = -1;
        o.resolver_sock_ = -1;
    }
    auto operator=(DnsServer&& o) noexcept -> DnsServer& {
        if (this != &o) {
            if (resolver_sock_ != -1)
                close(resolver_sock_);
            if (sockfd_ != -1)
                close(sockfd_);
            sockfd_ = o.sockfd_;
            resolver_sock_ = o.resolver_sock_;
            port_ = o.port_;
            resolver_ = std::move(o.resolver_);
            o.sockfd_ = -1;
            o.resolver_sock_ = -1;
        }
        return *this;
    }

    void run() {
        sockfd_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd_ == -1)
            throw std::runtime_error("socket creation failed");

        int reuse = 1;
        setsockopt(sockfd_, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port_);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        if (bind(sockfd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
            throw std::runtime_error("bind failed");

        if (resolver_) {
            resolver_sock_ = socket(AF_INET, SOCK_DGRAM, 0);
            if (resolver_sock_ == -1)
                throw std::runtime_error("resolver socket creation failed");
        }

        std::byte buffer[512];
        sockaddr_in client{};
        socklen_t client_len = sizeof(client);

        while (true) {
            auto n = recvfrom(sockfd_,
                              buffer,
                              sizeof(buffer),
                              0,
                              reinterpret_cast<sockaddr*>(&client),
                              &client_len);
            if (n <= 0)
                break;

            std::vector<std::byte> response;
            if (resolver_) {
                response = handle_forwarding({buffer, static_cast<size_t>(n)});
            } else {
                response = create_response({buffer, static_cast<size_t>(n)});
            }

            sendto(sockfd_,
                   response.data(),
                   response.size(),
                   0,
                   reinterpret_cast<sockaddr*>(&client),
                   sizeof(client));
        }
    }
  private:
    auto handle_forwarding(std::span<const std::byte> query) -> std::vector<std::byte> {
        auto msg = DnsMessage::parse(query);

        sockaddr_in resolver_addr{};
        resolver_addr.sin_family = AF_INET;
        resolver_addr.sin_port = htons(resolver_->port);
        inet_pton(AF_INET, resolver_->ip.c_str(), &resolver_addr.sin_addr);

        std::vector<std::vector<std::byte>> resolver_responses;

        for (size_t i = 0; i < msg.questions.size(); ++i) {
            DnsMessage single_q;
            single_q.header = msg.header;
            single_q.header.qdcount = 1;
            single_q.questions.push_back(msg.questions[i]);
            auto single_bytes = single_q.serialize();

            sendto(resolver_sock_,
                   single_bytes.data(),
                   single_bytes.size(),
                   0,
                   reinterpret_cast<sockaddr*>(&resolver_addr),
                   sizeof(resolver_addr));

            std::byte resp_buf[512];
            auto rn = recvfrom(resolver_sock_, resp_buf, sizeof(resp_buf), 0, nullptr, nullptr);
            if (rn > 0) {
                resolver_responses.emplace_back(resp_buf, resp_buf + rn);
            }
        }

        return build_forward_response(query, resolver_responses);
    }
};
