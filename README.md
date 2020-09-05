 # bq_websocket [![Build Status](https://travis-ci.org/bqqbarbhg/bq_websocket.svg?branch=master)](https://travis-ci.org/bqqbarbhg/bq_websocket) [![codecov](https://codecov.io/gh/bqqbarbhg/bq_websocket/branch/master/graph/badge.svg)](https://codecov.io/gh/bqqbarbhg/bq_websocket)


Single source file WebSocket library.
The library itself (bq_websocket.h/c) does not do any IO, but supports both callback and buffer based external IO.
The repository also contains a reference platform implementation (bq_websocket_platform.h/c) supporting non-blocking BSD sockets on Windows/Posix,
CFStream on Apple platforms, and browser WebSocket implementation on Emscripten. SSL is supported via OpenSSL if `BQWS_PT_USE_OPENSSL` is defined to a non-zero value.

The library is thread-safe and you can run IO code and send/receive messages in other threads in parallel.
Emscripten doesn't do proxying between WebWorkers so if you are running with a multi-threaded Emscripten
you need to make sure to call `bqws_update()` _only_ from a single thread for a socket instance!

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

// Renamed with .h suffix so the files don't build by default
#include "bq_websocket.c.h"
#include "bq_websocket_platform.c.h"
```

## Usage

### Client (using bq_websocket_platform.h)

```c
bqws_socket *ws = bqws_pt_connect("ws://echo.websocket.org", NULL, NULL, NULL);
bqws_send_text(ws, "Hello world!");

// bq_websocket_platform.h uses non-blocking IO so we need to poll here
for (;;) {
    bqws_update(ws);
    bqws_msg *msg = bqws_recv(ws);
    if (msg) {
        assert(msg->type == BQWS_MSG_TEXT);
        printf("Received message: %s\n", msg->data);
        bqws_free_msg(msg);
        break;
    }
    sleep(1);
}

bqws_free_socket(ws);
```

## License

```
------------------------------------------------------------------------------
This software is available under 2 licenses -- choose whichever you prefer.
------------------------------------------------------------------------------
ALTERNATIVE A - MIT License
Copyright (c) 2020 Samuli Raivio
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
------------------------------------------------------------------------------
ALTERNATIVE B - Public Domain (www.unlicense.org)
This is free and unencumbered software released into the public domain.
Anyone is free to copy, modify, publish, use, compile, sell, or distribute this
software, either in source code form or as a compiled binary, for any purpose,
commercial or non-commercial, and by any means.
In jurisdictions that recognize copyright laws, the author or authors of this
software dedicate any and all copyright interest in the software to the public
domain. We make this dedication for the benefit of the public at large and to
the detriment of our heirs and successors. We intend this dedication to be an
overt act of relinquishment in perpetuity of all present and future rights to
this software under copyright law.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
----------------------------------------
```
