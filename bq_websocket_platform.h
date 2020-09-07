#ifndef BQ_WEBSOCKET_PLATFORM_H_INCLUDED
#define BQ_WEBSOCKET_PLATFORM_H_INCLUDED

/*
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
*/

#include "bq_websocket.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BQWS_PT_MAX_ADDRESS_SIZE 16
#define BQWS_PT_MAX_ADDRESS_FORMAT_LENGTH 64

typedef struct bqws_pt_server bqws_pt_server;

typedef enum bqws_pt_error_type {
	BQWS_PT_ERRTYPE_NONE,

	// bqws_pt_error_code
	BQWS_PT_ERRTYPE_PT,

	// Windows Sockets error codes
	// https://docs.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2
	BQWS_PT_ERRTYPE_WSA,

	// POSIX errno codes
	// https://www-numi.fnal.gov/offline_software/srt_public_context/WebDocs/Errors/unix_system_errors.html
	BQWS_PT_ERRTYPE_POSIX,

	// getaddrinfo() error codes
	// http://man7.org/linux/man-pages/man3/getaddrinfo.3.html
	BQWS_PT_ERRTYPE_GETADDRINFO,

	// OpenSSL error codes
	BQWS_PT_ERRTYPE_OPENSSL,

} bqws_pt_error_type;

typedef enum bqws_pt_error_code {
	BQWS_PT_OK,
	BQWS_PT_ERR_NO_TLS,
	BQWS_PT_ERR_NO_SERVER_SUPPORT,
	BQWS_PT_ERR_OUT_OF_MEMORY,
	BQWS_PT_ERR_BAD_URL,
} bqws_pt_error_code;

typedef struct bqws_pt_error {
	const char *function;
	bqws_pt_error_type type;
	int64_t data;
} bqws_pt_error;

typedef enum bqws_pt_address_type {
	BQWS_PT_ADDRESS_UNKNOWN,
	BQWS_PT_ADDRESS_WEBSOCKET,
	BQWS_PT_ADDRESS_IPV4,
	BQWS_PT_ADDRESS_IPV6,
} bqws_pt_address_type;

typedef struct bqws_pt_address {
	bqws_pt_address_type type;
	uint16_t port;
	uint8_t address[BQWS_PT_MAX_ADDRESS_SIZE];
} bqws_pt_address;

typedef struct bqws_pt_init_opts {

	// CA certificate file location
	// For example: https://curl.haxx.se/docs/caextract.html
	const char *ca_filename;

} bqws_pt_init_opts;

typedef struct bqws_pt_connect_opts {

	// Disable host verification for TLS (secure) connections
	bool insecure_no_verify_host;

} bqws_pt_connect_opts;

typedef struct bqws_pt_listen_opts {

	// Use TLS for incoming connections
	bool secure;

	// TLS certificate, used only if `secure`
	const char *certificate_file; // Passed to `SSL_CTX_use_certificate_file()`
	const char *private_key_file; // Passed to `SSL_CTX_use_PrivateKey_file()`

	// Port to bind to
	// default: 80 if `!secure`, 443 if `secure`
	uint16_t port;

	// Number of connections to queue for `bqws_pt_accept()`
	// default: 128
	size_t backlog;

	// Attempt to share a port with other processes ie. `SO_REUSEPORT`
	bool reuse_port;

	// Allocator callbacks
	bqws_allocator allocator;

} bqws_pt_listen_opts;

// -- Global initialization

// Call these before/after any other functions
bool bqws_pt_init(const bqws_pt_init_opts *opts);
void bqws_pt_shutdown();

// Thread local error
void bqws_pt_clear_error();
bool bqws_pt_get_error(bqws_pt_error *err);

// -- Platform socket creation

// Client

bqws_socket *bqws_pt_connect(const char *url, const bqws_pt_connect_opts *pt_opts, const bqws_opts *opts, const bqws_client_opts *client_opts);
bqws_socket *bqws_pt_connect_url(const bqws_url *url, const bqws_pt_connect_opts *pt_opts, const bqws_opts *opts, const bqws_client_opts *client_opts);

// Server

bqws_pt_server *bqws_pt_listen(const bqws_pt_listen_opts *pt_opts);
void bqws_pt_free_server(bqws_pt_server *sv);

bqws_socket *bqws_pt_accept(bqws_pt_server *sv, const bqws_opts *opts, const bqws_server_opts *server_opts);

// Query

bqws_pt_address bqws_pt_get_address(const bqws_socket *ws);

// -- Utility

void bqws_pt_format_address(char *dst, size_t size, const bqws_pt_address *addr);

void bqws_pt_get_error_desc(char *dst, size_t size, const bqws_pt_error *err);

void bqws_pt_sleep_ms(uint32_t ms);

const char *bqws_pt_error_type_str(bqws_pt_error_type type);
const char *bqws_pt_error_code_str(bqws_pt_error_code err);

#ifdef __cplusplus
}
#endif

#endif
