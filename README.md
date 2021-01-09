 # bq_websocket [![CI](https://github.com/bqqbarbhg/bq_websocket/workflows/CI/badge.svg)](https://github.com/bqqbarbhg/bq_websocket/actions)


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

[//]: # (example readme_client_usage.c)
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

### Server (using bq_websocket_platform.h)

[//]: # (example readme_server_usage.c)
```c
#include "bq_websocket.h"
#include "bq_websocket_platform.h"
#include <stddef.h> // For size_t, NULL
#include <stdio.h> // For printf()
#include <string.h> // For strcmp()

#define MAX_CLIENTS 128
bqws_socket *clients[MAX_CLIENTS];

int main()
{
    bqws_pt_init(NULL);
    bqws_pt_server *sv = bqws_pt_listen(NULL);

    // bq_websocket_platform.h uses non-blocking IO so we need to poll here
    for (;;) {

        // Accept new connections
        bqws_socket *new_ws = bqws_pt_accept(sv, NULL, NULL);
        if (new_ws) {
            for (size_t i = 0; i < MAX_CLIENTS; i++) {
                if (!clients[i]) {
                    bqws_server_accept(new_ws, NULL);
                    clients[i] = new_ws;
                    new_ws = NULL; // Found slot, don't delete below
                    break;
                }
            }
            bqws_free_socket(new_ws);
        }

        // Update existing clients
        for (size_t i = 0; i < MAX_CLIENTS; i++) {
            bqws_socket *ws = clients[i];
            if (!ws) continue;

            bqws_update(ws);
            bqws_msg *msg;
            while ((msg = bqws_recv(ws)) != NULL) {
                if (msg->type == BQWS_MSG_TEXT && !strcmp(msg->data, "PING")) {
                    bqws_send_text(ws, "PONG");
                } else {
                    bqws_close(ws, BQWS_CLOSE_GENERIC_ERROR, NULL, 0);
                }
                bqws_free_msg(msg);
            }

            if (bqws_is_closed(ws)) {
                // Free the socket and slot
                bqws_free_socket(ws);
                clients[i] = NULL;
            }
        }

        bqws_pt_sleep_ms(10);
    }

    bqws_pt_free_server(sv);
    bqws_pt_shutdown();
}
```

## Integration

All you need to do is to add bq_websocket.c/h (and optionally bq_websocket_platform.c/h) to your build.
Alternatively you can include the implementation files as (either C or C++) headers to supply defines to customize their behavior:

```cpp
// Override the default/platform allocators, you don't need to do this at compile-time
// if you supply custom allocators using the bqws_opts struct!
#define bqws_malloc(size) my_alloc(size)
#define bqws_realloc(ptr, old_size, new_size) my_realloc(ptr, old_size, new_size)
#define bqws_free(ptr, size) my_free(ptr, size)

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
