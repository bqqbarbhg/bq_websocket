 # bq_websocket [![Build Status](https://travis-ci.org/bqqbarbhg/bq_websocket.svg?branch=master)](https://travis-ci.org/bqqbarbhg/bq_websocket) [![codecov](https://codecov.io/gh/bqqbarbhg/bq_websocket/branch/master/graph/badge.svg)](https://codecov.io/gh/bqqbarbhg/bq_websocket)


Single source file WebSocket library.
The library itself (bq_websocket.h/c) does not do any IO, but supports both callback and buffer based external IO.
The repository also contains a reference platform implementation (bq_websocket_platform.h/c) supporting non-blocking BSD sockets on Windows/Posix,
CFStream on Apple platforms, and browser WebSocket implementation on Emscripten. SSL is supported via OpenSSL if `BQWS_PT_USE_OPENSSL` is defined to a non-zero value.

The library is thread-safe and you can run IO code and send/receive messages in other threads in parallel.
Emscripten doesn't do proxying between WebWorkers so if you are running in a multi-threaded environment
make sure to call `bqws_update()` _only_ from a single thread for a socket instance!

The library is dual licensed under **public domain** and **MIT**, you can choose which one you prefer! See LICENSE for details.

## Usage

### Client (using bq_websocket_platform.h)

```c
#include "bq_websocket.h"
#include "bq_websocket_platform.h"
#include <stdio.h> // For printf()

int main()
{
    bqws_pt_init(NULL);
    bqws_socket *ws = bqws_pt_connect("ws://echo.websocket.org", NULL, NULL, NULL);
    bqws_send_text(ws, "Hello world!");

    // bq_websocket_platform.h uses non-blocking IO so we need to poll here
    for (;;) {
        bqws_update(ws);
        bqws_msg *msg = bqws_recv(ws);
        if (msg) {
            if (msg->type == BQWS_MSG_TEXT) {
                printf("Received message: %s\n", msg->data);
            } else if (msg->type == BQWS_MSG_BINARY) {
                printf("Received binary message: %zu bytes\n", msg->size);
            }
            bqws_free_msg(msg);
            break;
        }
        bqws_pt_sleep_ms(10);
    }

    bqws_free_socket(ws);
    bqws_pt_shutdown();
}
```

## Integration

All you need to do is to add bq_websocket.c/h (and optionally bq_websocket_platform.c/h) to your build.
Alternatively you can include the implementation files as headers to supply defines to customize their behavior:

```cpp
// Override the default/platform allocators, you don't need to do this at compile-time
// if you supply custom allocators using the bqws_opts struct!
#define bqws_malloc(size) my_alloc(size)
#define bqws_realloc(ptr, size) my_realloc(ptr, size)
#define bqws_free(ptr) my_free(ptr)

// Custom assert and force-enable debug
#define bqws_assert(cond) my_assert(cond)
#define BQWS_DEBUG 1

// Custom mutex implementation
#define bqws_mutex my_mutex_t
#define bqws_mutex_init(m) my_mutex_init(m)
#define bqws_mutex_free(m) my_mutex_free(m)
#define bqws_mutex_lock(m) my_mutex_lock(m)
#define bqws_mutex_unlock(m) my_mutex_unlock(m)

// Disable the default mutex
// #define BQWS_SINGLE_THREAD 1

// Use OpenSSL for platform TLS
#define BQWS_PT_USE_OPENSSL 1

// Renamed with .h suffix so the files don't build by default
#include "bq_websocket.c.h"
#include "bq_websocket_platform.c.h"
```
