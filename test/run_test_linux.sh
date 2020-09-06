set -eux

python3 test/verify_mutexes.py
pushd $(dirname "$0")
cd ..
mkdir -p build
cd build
clang -g -std=gnu99 -Wno-unused-value -lpthread -D_GNU_SOURCE ../bq_websocket.c ../test/test_self.c -o test_self_push
clang -g -std=gnu99 -Wno-unused-value -lpthread -DTEST_PULL -D_GNU_SOURCE ../bq_websocket.c ../test/test_self.c -o test_self_pull
clang -g -std=gnu99 -Wno-unused-value -lpthread -DUSE_CASE_FILES -D_GNU_SOURCE ../bq_websocket.c ../test/fuzz/fuzz_client_handshake.c -o fuzz_client_handshake_cases
clang -g -std=gnu99 -Wno-unused-value -lpthread -DUSE_CASE_FILES -D_GNU_SOURCE ../bq_websocket.c ../test/fuzz/fuzz_server_handshake.c -o fuzz_server_handshake_cases
clang -g -std=gnu99 -Wno-unused-value -lpthread -DUSE_CASE_FILES -D_GNU_SOURCE ../bq_websocket.c ../test/fuzz/fuzz_protocol.c -o fuzz_protocol_cases
clang -g -std=gnu99 -Wno-unused-value -lpthread -DNO_TLS -D_GNU_SOURCE ../bq_websocket.c ../bq_websocket_platform.c ../examples/echo_client_pt.c -o example_echo_client_pt
tar -xzf ../test/fuzz/fuzz_test_cases.tar.gz
./test_self_push
./test_self_pull
./fuzz_client_handshake_cases fuzz_test_cases/fuzz_
./fuzz_server_handshake_cases fuzz_test_cases/fuzz_
./fuzz_protocol_cases fuzz_test_cases/fuzz_
./example_echo_client_pt
popd
