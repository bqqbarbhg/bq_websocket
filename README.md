 # bq_websocket [![Build Status](https://travis-ci.org/bqqbarbhg/bq_websocket.svg?branch=master)](https://travis-ci.org/bqqbarbhg/bq_websocket) [![codecov](https://codecov.io/gh/bqqbarbhg/bq_websocket/branch/master/graph/badge.svg)](https://codecov.io/gh/bqqbarbhg/bq_websocket)


Single source file WebSocket library.
The library itself (bq_websocket.h/c) does not do any IO, but supports both callback and buffer based external IO.
The repository also contains a reference platform implementation (bq_websocket_platform.h/c) supporting non-blocking BSD sockets on Windows/Posix,
CFStream on Apple platforms, and browser WebSocket implementation on Emscripten. SSL is supported via OpenSSL if `BQWS_PT_USE_OPENSSL` is defined to a non-zero value.
