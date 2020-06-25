 # bq_websocket [![Build Status](https://travis-ci.org/bqqbarbhg/bq_websocket.svg?branch=master)](https://travis-ci.org/bqqbarbhg/bq_websocket) [![codecov](https://codecov.io/gh/bqqbarbhg/bq_websocket/branch/master/graph/badge.svg)](https://codecov.io/gh/bqqbarbhg/bq_websocket)


Single source file WebSocket library.
The library itself (bq_websocket.h/c) does not do any IO, but supports both callback and buffer based external IO.
The repository also contains a reference platform implementation (bq_websocket_platform.h/c) supporting non-blocking BSD sockets on Windows/Posix,
CFStream on Apple platforms, and browser WebSocket implementation on Emscripten. SSL is supported via OpenSSL if `BQWS_PT_USE_OPENSSL` is defined to a non-zero value.

## Usage (using bq_websocket_platform.h)

### Client

```c
bqws_socket *ws = bqws_pt_connect("ws://demos.kaazing.com/echo", NULL, NULL, NULL);
bqws_send_text(ws, "Hello world!");

// bq_websocket_platform uses non-blockin IO so we need to poll here
for (;;) {
    bqws_update(ws);
    bqws_msg *msg = bqws_recv(ws);
    if (msg) {
        assert(msg->type == BQWS_MSG_TEXT);
        printf("Received message: %s\n", msg->data);
        bqws_free_msg(msg);
        break;
    }
}

bqws_free_socket(ws);
```
