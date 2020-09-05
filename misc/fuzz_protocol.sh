#!/usr/bin/env bash

afl-clang-fast bq_websocket.c test/fuzz_protocol.c -lpthread -o build/fuzz_protocol$1
afl-fuzz -i test/fuzz_handshake_input -o build/fuzz_protocol_findings$1 build/fuzz_protocol$1
