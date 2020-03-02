#ifndef BQ_WEBSOCKET_H_INCLUDED
#define BQ_WEBSOCKET_H_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct bqws_socket bqws_socket;

typedef enum bqws_error {
	BQWS_OK = 0,

	// Unknown error from non-BQWS peer
	BQWS_ERR_UNKNOWN,

	// Rejected with `bqws_server_reject()`
	BQWS_ERR_SERVER_REJECT,

	// Data over limits of `bqws_limits`
	BQWS_ERR_LIMIT_MAX_MEMORY_USED,
	BQWS_ERR_LIMIT_MAX_RECV_MSG_SIZE,
	BQWS_ERR_LIMIT_MAX_HANDSHAKE_SIZE,

	BQWS_ERR_PING_TIMEOUT,
	BQWS_ERR_CLOSE_TIMEOUT,

	// Allocator returned NULL
	BQWS_ERR_ALLOCATOR,

	BQWS_ERR_BAD_CONTINUATION,
	BQWS_ERR_UNFINISHED_PARTIAL,
	BQWS_ERR_PARTIAL_CONTROL,
	BQWS_ERR_BAD_OPCODE,
	BQWS_ERR_RESERVED_BIT,
	BQWS_ERR_IO_WRITE,
	BQWS_ERR_IO_READ,
	BQWS_ERR_BAD_HANDSHAKE,
	BQWS_ERR_UNSUPPORTED_VERSION,
	BQWS_ERR_TOO_MANY_HEADERS,
	BQWS_ERR_TOO_MANY_PROTOCOLS,
	BQWS_ERR_HEADER_KEY_TOO_LONG,
	BQWS_ERR_HEADER_BAD_ACCEPT,
	BQWS_ERR_HEADER_PARSE,
} bqws_error;

typedef enum bqws_state {
	BQWS_STATE_INVALID,
	BQWS_STATE_CONNECTING,
	BQWS_STATE_OPEN,
	BQWS_STATE_CLOSING,
	BQWS_STATE_CLOSED,
} bqws_state;

typedef enum bqws_close_reason {
	BQWS_CLOSE_INVALID = 0,

	BQWS_CLOSE_NORMAL            = 1000,
	BQWS_CLOSE_GOING_AWAY        = 1001,
	BQWS_CLOSE_PROTOCOL_ERROR    = 1002,
	BQWS_CLOSE_UNSUPPORTED_TYPE  = 1003,
	BQWS_CLOSE_NO_REASON         = 1005,
	BQWS_CLOSE_ABNORMAL          = 1006,
	BQWS_CLOSE_BAD_DATA          = 1007,
	BQWS_CLOSE_GENERIC_ERROR     = 1008,
	BQWS_CLOSE_MESSAGE_TOO_BIG   = 1009,
	BQWS_CLOSE_EXTENSION_MISSING = 1010,
	BQWS_CLOSE_SERVER_ERROR      = 1011,
} bqws_close_reason;

typedef enum bqws_msg_type {

	BQWS_MSG_INVALID = 0,

	// Basic full text/binary messages
	BQWS_MSG_TEXT = 0x0001,
	BQWS_MSG_BINARY = 0x0002,

	// Reported only if `bqws_opts.recv_partial_messages` is `true`
	BQWS_MSG_PARTIAL_TEXT = 0x0011,
	BQWS_MSG_PARTIAL_BINARY = 0x0012,
	BQWS_MSG_FINAL_TEXT   = 0x0111,
	BQWS_MSG_FINAL_BINARY   = 0x0112,

	// Reported only if `bqws_opts.recv_control_messages` is `true`
	BQWS_MSG_CONTROL_CLOSE     = 0x1000,
	BQWS_MSG_CONTROL_PING      = 0x2000,
	BQWS_MSG_CONTROL_PONG      = 0x3000,

	// Masks for inspecting groups of types
	BQWS_MSG_TYPE_MASK    = 0x000f,
	BQWS_MSG_PARTIAL_BIT  = 0x0010,
	BQWS_MSG_FINAL_BIT    = 0x0100,
	BQWS_MSG_CONTROL_MASK = 0xf000,

} bqws_msg_type;

// Message buffers managed by bq_websocket.

typedef struct bqws_msg {

	// The socket that originally allocated this message
	bqws_socket *socket;

	// Type enum/bitmask
	bqws_msg_type type;

	// Size of the message in bytes, may be smaller than the
	// allocated buffer at `data`
	size_t size;

	// Size of `data` in bytes
	size_t capacity;

	char data[];
} bqws_msg;

// Message header

typedef void *bqws_alloc_fn(void *user, size_t size);
typedef void *bqws_realloc_fn(void *user, void *ptr, size_t old_size, size_t new_size);
typedef void bqws_free_fn(void *user, void *ptr, size_t size);

typedef size_t bqws_io_send_fn(void *user, bqws_socket *ws, const void *data, size_t size);
typedef size_t bqws_io_recv_fn(void *user, bqws_socket *ws, void *data, size_t max_size, size_t min_size);
typedef void bqws_io_notify_fn(void *user, bqws_socket *ws);
typedef bool bqws_io_flush_fn(void *user, bqws_socket *ws);
typedef void bqws_io_close_fn(void *user, bqws_socket *ws);

typedef bool bqws_message_fn(void *user, bqws_socket *ws, bqws_msg *msg);
typedef bool bqws_send_message_fn(void *user, bqws_socket *ws, bqws_msg *msg);
typedef void bqws_peek_fn(void *user, bqws_socket *ws, bqws_msg *msg, bool received);
typedef void bqws_log_fn(void *user, bqws_socket *ws, const char *line);

typedef struct bqws_allocator {
	void *user;
	bqws_alloc_fn *alloc_fn;
	bqws_realloc_fn *realloc_fn;
	bqws_free_fn *free_fn;
} bqws_allocator;

typedef struct bqws_io {
	void *user;
	bqws_io_send_fn *send_fn;
	bqws_io_recv_fn *recv_fn;
	bqws_io_notify_fn *notify_fn;
	bqws_io_flush_fn *flush_fn;
	bqws_io_close_fn *close_fn;
} bqws_io;

typedef struct bqws_limits {

	// Maximum total memory used
	// default: 262144
	size_t max_memory_used;

	// Maximum received message length
	// default: 262144
	size_t max_recv_msg_size;

	// Maximum handshake length
	// default: 262144
	size_t max_handshake_size;

} bqws_limits;

typedef struct bqws_opts {
	bqws_io io;
	bqws_allocator allocator;
	bqws_limits limits;

	// Message callback
	bqws_message_fn *message_fn;
	void *message_user;

	// Peek at all control/partial incoming messages even if
	// `recv_partial_messages` and `recv_control_messages are disabled.
	bqws_peek_fn *peek_fn;
	void *peek_user;

	// Verbose log of all events for this socket
	bqws_log_fn *log_fn;
	void *log_user;

	// Send messages manually without IO
	bqws_send_message_fn *send_message_fn;
	void *send_message_user;

	// User data block, if `user_size > 0` but `user_data == NULL`
	// the data will be zero-initialized
	void *user_data;
	size_t user_size;

	// How often (milliseconds) to send PING messages if there is no traffic,
	// use SIZE_MAX to disable automatic PING
	// default: server: 20000, client: 10000
	size_t ping_interval;

	// How long to wait (milliseconds) for the close response before forcing the
	// state to be BQWS_STATE_CLOSED. Use SIZE_MAX to disable
	// the close timeout.
	// default: 5000
	size_t close_timeout;

	// How long to wait (milliseconds) for a ping response before forcing
	// the state to be BQWS_STATE_CLOSED. Use SIZE_MAX to disable.
	// the close timeout.
	// default: 4 * ping_interval
	size_t ping_response_timeout;

	// Name for the socket for debugging
	const char *name;

	// If set returns `BQWS_MSG_PARTIAL_*` messages from `bqws_recv()`
	bool recv_partial_messages;

	// If set returns `BQWS_MSG_CONTROL_*` messages from `bqws_recv()`
	bool recv_control_messages;

	// Mask messages sent by the server as well
	bool mask_server;

	// Don't mask client messages, violates the spec!
	bool unsafe_dont_mask_client;

	// Start the connection in BQWS_STATE_OPEN state
	bool skip_handshake;

} bqws_opts;

typedef struct bqws_header {
	const char *name;
	const char *value;
} bqws_header;

#define BQWS_MAX_HEADERS 64
#define BQWS_MAX_PROTOCOLS 64

typedef struct bqws_client_opts {

	// Headers
	const char *path;
	const char *host;
	const char *origin;

	const char *protocols[BQWS_MAX_PROTOCOLS];
	size_t num_protocols;

	bqws_header headers[BQWS_MAX_HEADERS];
	size_t num_headers;

	// Random seed
	char random_key[16];
	char random_key_base64[32];

} bqws_client_opts;

// Call `bqws_server_accept()` or `bqws_server_reject()` here to handle the socket
typedef void bqws_verify_fn(void *user, bqws_socket *ws, const bqws_client_opts *opts);

typedef struct bqws_server_opts {

	// Automatically verify connections matching this filter
	bqws_client_opts *verify_filter;

	// Verify callback, same as polling `bqws_server_get_client_options()`
	// and calling `bqws_server_accept()`
	bqws_verify_fn *verify_fn;
	void *verify_user;

} bqws_server_opts;

typedef struct bqws_url {
	bool secure;
	uint16_t port;
	char scheme[16];
	char host[256];
	const char *path;
} bqws_url;

// -- WebSocket management

bqws_socket *bqws_new_client(const bqws_opts *opts, const bqws_client_opts *client_opts);
bqws_socket *bqws_new_server(const bqws_opts *opts, const bqws_server_opts *server_opts);
void bqws_close(bqws_socket *ws, bqws_close_reason reason, const void *data, size_t size);
void bqws_free_socket(bqws_socket *ws);

// -- Server connect

// Accept or reject connections based on headers.
// Valid only until `bqws_server_connect()` or `bqws_free_socket()`!
bqws_client_opts *bqws_server_get_client_opts(bqws_socket *ws);
void bqws_server_accept(bqws_socket *ws, const char *protocol);
void bqws_server_reject(bqws_socket *ws);

// -- State query

bqws_state bqws_get_state(const bqws_socket *ws);
bqws_error bqws_get_error(const bqws_socket *ws);
bool bqws_is_closed(const bqws_socket *ws);
size_t bqws_get_memory_used(const bqws_socket *ws);
bool bqws_is_server(const bqws_socket *ws);
void *bqws_user_data(const bqws_socket *ws);
size_t bqws_user_data_size(const bqws_socket *ws);
const char *bqws_get_name(const bqws_socket *ws);

// Peer closing
bqws_close_reason bqws_get_peer_close_reason(const bqws_socket *ws);
bqws_error bqws_get_peer_error(const bqws_socket *ws);

// Get the chosen protocol, returns "" if none chosen but the connection is open
// Returns NULL if the connection is not established
const char *bqws_get_protocol(const bqws_socket *ws);

// Receive a message, use `bqws_free_msg()` to free the returned pointer
bqws_msg *bqws_recv(bqws_socket *ws);
void bqws_free_msg(bqws_msg *msg);

// Single message
void bqws_send(bqws_socket *ws, bqws_msg_type type, const void *data, size_t size);
void bqws_send_binary(bqws_socket *ws, const void *data, size_t size);
void bqws_send_text(bqws_socket *ws, const char *str);
void bqws_send_text_len(bqws_socket *ws, const void *str, size_t len);

// Write to socket-provided memory
bqws_msg *bqws_allocate_msg(bqws_socket *ws, bqws_msg_type type, size_t size);
void bqws_send_msg(bqws_socket *ws, bqws_msg *msg);

// Streaming messages
void bqws_send_begin(bqws_socket *ws, bqws_msg_type type);
void bqws_send_append(bqws_socket *ws, const void *data, size_t size);
void bqws_send_append_str(bqws_socket *ws, const void *str);
void bqws_send_append_msg(bqws_socket *ws, bqws_msg *msg);
void bqws_send_finish(bqws_socket *ws);

// Send manual control messages
void bqws_send_ping(bqws_socket *ws, const void *data, size_t size);
void bqws_send_pong(bqws_socket *ws, const void *data, size_t size);

// Keep the socket alive, reads/writes buffered data and responds to pings/pongs
// Semantically equivalent to bqws_update_state() and bqws_update_io()
void bqws_update(bqws_socket *ws);

void bqws_update_state(bqws_socket *ws);
void bqws_update_io(bqws_socket *ws);
void bqws_update_io_read(bqws_socket *ws);
void bqws_update_io_write(bqws_socket *ws);

// Manual IO
size_t bqws_read_from(bqws_socket *ws, const void *data, size_t size);
size_t bqws_write_to(bqws_socket *ws, void *data, size_t size);

// Direct control
void bqws_direct_push_msg(bqws_socket *ws, bqws_msg *msg);
void bqws_direct_set_override_state(bqws_socket *ws, bqws_state state);

// -- Utility

bool bqws_parse_url(bqws_url *url, const char *str);

const char *bqws_error_str(bqws_error error);
const char *bqws_msg_type_str(bqws_msg_type type);
const char *bqws_state_str(bqws_state state);

#endif