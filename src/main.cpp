#include "server.hpp"

#include <iostream>
#include <string_view>

int main(int argc, char* argv[]) {
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    setbuf(stdout, nullptr);

    std::optional<ResolverAddr> resolver;
    for (int i = 1; i < argc; ++i) {
        if (std::string_view{argv[i]} == "--resolver" && i + 1 < argc) {
            resolver = parse_resolver(argv[++i]);
        }
    }

    DnsServer server{2053, std::move(resolver)};
    server.run();
}
