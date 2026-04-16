# Mini DNS

A lightweight DNS server implementation in C++23.

## Current Features

- DNS message header parsing and response generation (RFC 1035)
- UDP socket server listening on port 2053
- Responds to DNS queries with correct header fields

## Architecture

```
src/
├── main.cpp                  # Entry point
├── server.hpp                # DnsServer - UDP socket lifecycle & event loop
└── protocol/
    ├── header.hpp            # DnsHeader - parse/serialize DNS header
    └── message.hpp           # DnsMessage - top-level DNS message structure
```

- **protocol/** — Protocol layer: data structures and encoding/decoding for DNS packet format
- **server.hpp** — Transport layer: socket management, request/response handling
- **main.cpp** — Minimal entry point

## Build & Test

```sh
./build.sh && ./run_tests.sh
```

## Record Types

*To be implemented.*

## Recursive Resolution

*To be implemented.*
