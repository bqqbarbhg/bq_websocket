#!/usr/bin/env bash

afl-clang-fast bq_websocket.c test/fuzz_server_handshake.c -lpthread -o build/fuzz_server_handshake$1
afl-fuzz -i test/fuzz_handshake_input -o build/fuzz_server_handshake_findings$1 build/fuzz_server_handshake$1
