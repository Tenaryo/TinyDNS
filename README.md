# Mini DNS

A zero-dependency, C++23 DNS server — modern language features, clean architecture, and strict compile-time safety.

## Highlights

- **C++23 throughout** — structured bindings, `std::byte`, `std::span`, C++20 ranges concepts, `std::from_chars` zero-allocation parsing
- **Zero external dependencies** — pure C++23 + POSIX sockets, no third-party libraries
- **Compile-time safety** — `-Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion` enabled globally via CMake INTERFACE target
- **RFC 1035 compliant** — full DNS wire format: headers, questions, resource records, label compression with pointer loops
- **Forwarding resolver** — optional `--resolver <ip>:<port>` to forward queries to upstream DNS servers
- **Separation of concerns** — protocol layer (parse/serialize) fully decoupled from transport layer (UDP socket I/O)

## Architecture

```
src/
├── main.cpp                          # Entry point & CLI argument parsing
├── server.hpp                        # Transport: UDP socket lifecycle, event loop, forwarding
├── resolver.hpp                      # Resolver address parser (std::from_chars)
└── protocol/
    ├── codec.hpp                     # Shared big-endian read/write utilities
    ├── header.hpp                    # DNS header (12 bytes)
    ├── label.hpp                     # Label sequence parser with compression pointer support
    ├── question.hpp                  # DNS question section
    ├── resource_record.hpp           # DNS resource record section
    └── message.hpp                   # Top-level DNS message composition
```

**Protocol layer** (`protocol/`) handles all wire-format encoding/decoding with:
- Pre-allocated buffers (`reserve()`) to eliminate serialization-time heap reallocations
- Bounds checking on every parse — malformed packets throw rather than cause UB
- Deduplicated codec utilities (`read_u16`, `append_labels`, etc.)

**Transport layer** (`server.hpp`) manages UDP sockets, the event loop, and optional per-question forwarding to an upstream resolver.

## Usage

```sh
#Build(requires GCC 13 + and Ninja)
./build.sh

#Run as a standalone DNS server(port 2053)
./build/dns-server

#Run as a forwarding resolver
./build/dns-server --resolver 8.8.8.8:53
```

## Build & Test

```sh
./build.sh && ./run_tests.sh
```

20 tests covering header roundtrip, question/record parse+serialize, compressed pointer resolution, multi-question responses, and forwarding logic.

## Requirements

- C++23 compiler (GCC 13+, Clang 17+)
- Ninja (optional, `build.sh` defaults to Ninja)
- CMake 3.21+

## License

MIT
