#!/usr/bin/env bash

mkdir -p build/fuzz_server_handshake$1_input
cp -r test/fuzz/fuzz_handshake_input/* build/fuzz_server_handshake$1_input
afl-clang-fast bq_websocket.c test/fuzz/fuzz_server_handshake.c -lpthread -o build/fuzz_server_handshake$1
afl-fuzz -i build/fuzz_server_handshake$1_input -o build/fuzz_server_handshake$1_findings build/fuzz_server_handshake$1
