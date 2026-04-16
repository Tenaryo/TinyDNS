#include "server.hpp"

#include <iostream>

int main() {
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    setbuf(stdout, nullptr);

    DnsServer server{2053};
    server.run();
}
