#ifndef BQ_WEBSOCKET_PLATFORM_H_INCLUDED
#define BQ_WEBSOCKET_PLATFORM_H_INCLUDED

#include "bq_websocket.h"

#include <stdbool.h>
#include <stdint.h>

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
	const char *certificate_file;
	const char *private_key_file;

	// Port to bind to
	// default: 80 if `!secure`, 443 if `secure`
	uint16_t port;

	// Number of connections to queue for `bqws_pt_accept()`
	// default: 128
	size_t backlog;

} bqws_pt_listen_opts;

// -- Global initialization

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

// -- Utility

void bqws_pt_get_error_desc(char *dst, size_t size, const bqws_pt_error *err);

const char *bqws_pt_error_type_str(bqws_pt_error_type type);
const char *bqws_pt_error_code_str(bqws_pt_error_code err);

#endif
