#!/usr/bin/env bash

afl-clang-fast bq_websocket.c test/fuzz_client_handshake.c -lpthread -o build/fuzz_client_handshake$1
afl-fuzz -i test/fuzz_handshake_input -o build/fuzz_client_handshake_findings$1 build/fuzz_client_handshake$1
