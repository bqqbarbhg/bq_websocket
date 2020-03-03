#include "bq_websocket.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <stdarg.h>

// -- Config

#if defined(_MSC_VER)
	#define bqws_forceinline __forceinline

	#if defined(_M_IX86) || defined(_M_X64)
		#include <intrin.h>
		#include <xmmintrin.h>
		#define BQWS_USE_SSE 1
		#define bqws_cpu_time() (uint64_t)__rdtsc()
	#endif


#elif defined(__GNUC__) || defined(__clang__)
	#define bqws_forceinline __attribute__((always_inline))

	#if defined(__EMSCRIPTEN__)
		#include <emscripten/em_js.h>

		EM_JS(double, bqws_js_perfnow, (void), {
			return performance.now();
		});

		#define bqws_cpu_time() (uint64_t)(bqws_js_perfnow() * 1e3)

	#elif defined(__i386__) || defined(__x86_64__)

		#include <x86intrin.h>
		#include <xmmintrin.h>
		#define BQWS_USE_SSE 1
		#define bqws_cpu_time() (uint64_t)__rdtsc()

	#endif

#else
	#define bqws_forceinline
#endif

#ifndef bqws_assert
#include <assert.h>
#define bqws_assert(x) assert(x)
#endif


// TODO: QueryPerformanceCounter() or clock_gettime() might be faster
typedef clock_t bqws_timestamp;

static bqws_timestamp bqws_get_timestamp()
{
	return clock();
}

static size_t bqws_timestamp_delta_to_ms(bqws_timestamp begin, bqws_timestamp end)
{
	return (end - begin) * 1000 / CLOCKS_PER_SEC;
}

typedef struct {
	bool is_locked;
} bqws_mutex;

static void bqws_mutex_init(bqws_mutex *m)
{
	m->is_locked = false;
}

static void bqws_mutex_free(bqws_mutex *m)
{
	bqws_assert(!m->is_locked);
}

static void bqws_mutex_lock(bqws_mutex *m)
{
	bqws_assert(!m->is_locked);
	m->is_locked = true;
}
static void bqws_mutex_unlock(bqws_mutex *m)
{
	bqws_assert(m->is_locked);
	m->is_locked = false;
}

#define bqws_assert_locked(m) bqws_assert((m)->is_locked)

// -- Magic constants

#define BQWS_DELETED_MAGIC   0xbdbdbdbd
#define BQWS_SOCKET_MAGIC    0x7773636b
#define BQWS_MSG_MAGIC       0x776d7367
#define BQWS_FILTER_MAGIC    0x77666c74

#define CLIENT_KEY_BASE64_MAX_SIZE 32

// -- Types

// Message implementation struct, message data is always allocated
// to follow the struct in memory.

typedef struct bqws_msg_imp bqws_msg_imp;
struct bqws_msg_imp {
	uint32_t magic; // = BQWS_MSG_MAGIC

	// Socket that is responsible of freeing this message
	// or NULL if it's owned by the user.
	bqws_socket *owner;

	// Allocator used to allocate this message
	bqws_allocator allocator;

	// Linked list in `bqws_msg_queue`
	bqws_msg_imp *prev;

	bqws_msg msg;
};

#define msg_imp(msg) (bqws_msg_imp*)((char*)msg - offsetof(bqws_msg_imp, msg))
#define msg_alloc_size(msg) (sizeof(bqws_msg_imp) + (msg)->capacity)

typedef struct {
	bqws_mutex mutex;
	bqws_msg_imp *first, *last;

	size_t num_messages;
	size_t byte_size;

	uint64_t total_messages;
	uint64_t total_size;
} bqws_msg_queue;

typedef struct {
	bqws_msg_imp *msg;
	size_t offset;
	size_t header_offset;
	size_t header_size;
	bool finished;
	bool masked;
	uint32_t mask_key;
	bqws_msg_type partial_type;
} bqws_msg_buffer;

typedef struct {
	char *data;
	size_t size;
	size_t capacity;
	size_t write_offset;
	size_t read_offset;
} bqws_handshake_buffer;

typedef struct {
	uint32_t magic;

	const char *path;
	const char *host;
	const char *origin;

	const char *protocols[BQWS_MAX_PROTOCOLS];
	size_t num_protocols;

	size_t text_size;
	char text_data[];
} bqws_verify_filter;

// Random entropy source
typedef struct {
	uint64_t cpu_time_a;
	void (*function_pointer)(bqws_socket *ws, const bqws_client_opts *opts);
	void *stack_pointer;
	void *heap_pointer;
	clock_t clock;
	time_t time;
	uint64_t cpu_time_b;
} bqws_random_entropy;

typedef struct {
	uint8_t code_be[2];
	uint8_t magic[4];
	uint8_t error_be[4];
} bqws_err_close_data;

// Main socket/context type, passed everywhere as the first argument.

struct bqws_socket {

	// -- Constant data

	uint32_t magic; // = BQWS_SOCKET_MAGIC
	char *name; // Name high up for debugging
	bool is_server;

	// Copied from `opts`
	bqws_allocator allocator;
	bqws_io user_io;
	bqws_limits limits;
	bool recv_partial_messages;
	bool recv_control_messages;
	bool mask_server;
	bool unsafe_dont_mask_client;
	bqws_verify_fn *verify_fn;
	void *verify_user;
	bqws_message_fn *message_fn;
	void *message_user;
	bqws_peek_fn *peek_fn;
	void *peek_user;
	bqws_log_fn *log_fn;
	void *log_user;
	bool log_send;
	bool log_recv;
	bqws_send_message_fn *send_message_fn;
	void *send_message_user;
	size_t user_size;
	size_t ping_interval;
	size_t close_timeout;
	size_t ping_response_timeout;

	// -- Internally synchronized

	// Current error state, set to the first error that occurs
	// Error writes are protected by `err_mutex` checking `err` can
	// be done without a mutex to check for errors from the same thread.
	bqws_mutex err_mutex;
	bqws_error err;

	// Message queues
	bqws_msg_queue recv_partial_queue;
	bqws_msg_queue recv_queue;
	bqws_msg_queue send_queue;

	// -- State of the socket, errors 
	struct {
		bqws_mutex mutex;

		// Connection state
		bqws_state state;
		bqws_state override_state;

		// Pre-allocated error close message storage
		char error_msg_data[sizeof(bqws_msg_imp) + sizeof(bqws_err_close_data)];
		bqws_close_reason peer_reason;
		bqws_error peer_err;
		bool stop_write;
		bool stop_read;
		bool close_sent;
		bool close_received;
		bool io_closed;

		char *chosen_protocol;

		bqws_timestamp start_closing_ts;

		// Priority messages
		bqws_msg_imp *close_to_send;
		bqws_msg_imp *pong_to_send;
	
	} state;

	// -- Allocation
	struct {
		bqws_mutex mutex;

		// TODO: Make this atomic?
		// Total memory allocated through `allocator` at the moment
		size_t memory_used;
	} alloc;

	// -- IO
	struct {
		bqws_mutex mutex;

		bqws_timestamp last_write_ts;
		bqws_timestamp last_read_ts;
		bqws_timestamp last_ping_ts;
		size_t recv_partial_size;

		// Handshake
		bqws_handshake_buffer handshake;
		bqws_handshake_buffer handshake_overflow;
		bqws_client_opts *opts_from_client;
		char *client_key_base64;
		bool client_handshake_done;

		// Write/read buffers `recv_header` is also used to buffer
		// multiple small messages
		char recv_header[512];
		bqws_msg_buffer recv_buf;
		char send_header[16];
		bqws_msg_buffer send_buf;
	} io;

	// -- API
	struct {
		bqws_mutex mutex;

		bqws_msg_imp *next_partial_to_send;
		bqws_msg_type send_partial_type;
	} partial;

	// User data follows in memory
	char user_data[];
};

// -- Utility

// Mark the socket as failed with an error. Only updates the
// error flag if it's not set.

static void null_free(void *user, void *ptr, size_t size) { }

static void ws_log(bqws_socket *ws, const char *str)
{
	if (ws->log_fn) ws->log_fn(ws->log_user, ws, str);
}

static void ws_log2(bqws_socket *ws, const char *a, const char *b)
{
	if (!ws->log_fn) return;

	char line[256];
	size_t len_a = strlen(a);
	size_t len_b = strlen(b);
	bqws_assert(len_a + len_b < sizeof(line));

	char *ptr = line;
	memcpy(ptr, a, len_a); ptr += len_a;
	memcpy(ptr, b, len_b); ptr += len_b;
	*ptr = '\0';

	ws->log_fn(ws->log_user, ws, line);
}

static void ws_close(bqws_socket *ws)
{
	bqws_assert_locked(&ws->state.mutex);

	if (ws->state.state != BQWS_STATE_CLOSED) {
		ws_log(ws, "State: CLOSED");

		ws->state.state = BQWS_STATE_CLOSED;
		ws->state.stop_read = true;
		ws->state.stop_write = true;
	}
}

static void ws_fail(bqws_socket *ws, bqws_error err)
{
	bool should_close = false;

	bqws_mutex_lock(&ws->state.mutex);

	bqws_assert(err != BQWS_OK);

	bqws_mutex_lock(&ws->err_mutex);
	if (!ws->err) {
		// vvv Breakpoint here to stop on first error
		ws->err = err;

		bqws_mutex_unlock(&ws->err_mutex);

		ws_log2(ws, "Fail: ", bqws_error_str(err));

		// Try to send an error close message
		if (ws->state.state == BQWS_STATE_OPEN && !ws->state.close_to_send) {
			bqws_msg_imp *close_msg = (bqws_msg_imp*)ws->state.error_msg_data;
			close_msg->magic = BQWS_MSG_MAGIC;
			close_msg->allocator.free_fn = &null_free;
			close_msg->owner = ws;
			close_msg->prev = NULL;
			close_msg->msg.socket = ws;
			close_msg->msg.capacity = sizeof(bqws_err_close_data);
			close_msg->msg.size = sizeof(bqws_err_close_data);
			close_msg->msg.type = BQWS_MSG_CONTROL_CLOSE;

			bqws_close_reason reason;
			switch (err) {
			case BQWS_ERR_LIMIT_MAX_RECV_MSG_SIZE:
				reason = BQWS_CLOSE_MESSAGE_TOO_BIG;
				break;

			case BQWS_ERR_BAD_CONTINUATION:
			case BQWS_ERR_UNFINISHED_PARTIAL:
			case BQWS_ERR_PARTIAL_CONTROL:
			case BQWS_ERR_BAD_OPCODE:
			case BQWS_ERR_RESERVED_BIT:
				reason = BQWS_CLOSE_PROTOCOL_ERROR;
				break;

			default:
				reason = BQWS_CLOSE_SERVER_ERROR;
				break;
			}

			bqws_err_close_data *data = (bqws_err_close_data*)close_msg->msg.data;
			data->code_be[0] = (uint8_t)(reason >> 8);
			data->code_be[1] = (uint8_t)(reason >> 0);
			memcpy(data->magic, "BQWS", 4);
			data->error_be[0] = (uint8_t)(err >> 24);
			data->error_be[1] = (uint8_t)(err >> 16);
			data->error_be[2] = (uint8_t)(err >> 8);
			data->error_be[3] = (uint8_t)(err >> 0);

			ws->state.close_to_send = close_msg;
			ws->state.state = BQWS_STATE_CLOSING;
			ws->state.start_closing_ts = bqws_get_timestamp();

		} else if (ws->state.state == BQWS_STATE_CONNECTING) {

			// If there's an error during connection close
			// the connection immediately
			ws_close(ws);

		}

	} else {
		bqws_mutex_unlock(&ws->err_mutex);
	}

	// IO errors should close their respective channels
	if (err == BQWS_ERR_IO_READ) ws->state.stop_read = true;
	if (err == BQWS_ERR_IO_WRITE) ws->state.stop_write = true;

	bqws_mutex_unlock(&ws->state.mutex);
}

static void bqws_sha1(uint8_t digest[20], const void *data, size_t size);

// Callback writer

typedef struct {
	char *ptr, *end;
} bqws_mem_stream;

static size_t mem_stream_send(void *user, bqws_socket *ws, const void *data, size_t size)
{
	// Copy as many bytes as fit in the stream
	bqws_mem_stream *s = (bqws_mem_stream*)user;
	size_t left = s->end - s->ptr;
	size_t to_copy = size;
	if (to_copy > left) to_copy = left;
	memcpy(s->ptr, data, to_copy);
	s->ptr += to_copy;
	return to_copy;
}

static size_t mem_stream_recv(void *user, bqws_socket *ws, void *data, size_t max_size, size_t min_size)
{
	// Copy as many bytes as fit in the stream
	bqws_mem_stream *s = (bqws_mem_stream*)user;
	size_t left = s->end - s->ptr;
	size_t to_copy = max_size;
	if (to_copy > left) to_copy = left;
	memcpy(data, s->ptr, to_copy);
	s->ptr += to_copy;
	return to_copy;
}

// -- Allocation

// Direct allocator functions. Prefer using `ws_alloc()` if there is an `bqws_socket`
// avaialable (which there should almost always be). These functions just call the
// user callbacks or defaults passing in the user pointer.

static void *allocator_alloc(const bqws_allocator *at, size_t size);
static void *allocator_realloc(const bqws_allocator *at, void *ptr, size_t old_size, size_t new_size);
static void allocator_free(const bqws_allocator *at, void *ptr, size_t size);

static void *allocator_alloc(const bqws_allocator *at, size_t size)
{
	if (at->alloc_fn) {
		// User defined alloc directly
		return at->alloc_fn(at->user, size);
	} else if (at->realloc_fn) {
		// Realloc with zero initial size
		return at->realloc_fn(at->user, NULL, 0, size);
	} else {
		// Default: malloc()
		return malloc(size);
	}
}

static void *allocator_realloc(const bqws_allocator *at, void *ptr, size_t old_size, size_t new_size)
{
	if (old_size == 0) {
		// Realloc with `old_size==0` is equivalent to malloc
		return allocator_alloc(at, new_size);
	} else if (new_size == 0) {
		// Realloc with `new_size==0` is equivalent to free
		allocator_free(at, ptr, old_size);
		return NULL;
	}

	if (at->realloc_fn) {
		// User defined realloc directly
		return at->realloc_fn(at->user, ptr, old_size, new_size);
	} else if (at->alloc_fn) {
		// No realloc, but alloc is defined. Allocate and copy the data
		// if it succeeded and free the old pointer (if free is defined)
		void *new_ptr = at->alloc_fn(at->user, new_size);
		if (!new_ptr) return NULL;
		memcpy(new_ptr, ptr, old_size);
		if (at->free_fn) {
			at->free_fn(at->user, ptr, old_size);
		}
		return new_ptr;
	} else {
		// Default: realloc()
		return realloc(ptr, new_size);
	}
}

static void allocator_free(const bqws_allocator *at, void *ptr, size_t size)
{
	if (size == 0) return;
	bqws_assert(ptr != NULL);

	if (at->free_fn) {
		// Use defined free directly
		at->free_fn(at->user, ptr, size);
	} else if (at->realloc_fn) {
		// Use realloc with zero new size
		at->realloc_fn(at->user, ptr, size, 0);
	} else {
		bqws_assert(at->alloc_fn == NULL);

		// Default: free(), only if there is no user defined allocator
		free(ptr);
	}
}

// WebSocket allocation functions. These keep track of total used memory and
// update the error flag.

static bool ws_add_memory_used(bqws_socket *ws, size_t size)
{
	// TODO: Atomics
	bqws_mutex_lock(&ws->alloc.mutex);

	bool ok = (size <= ws->limits.max_memory_used - ws->alloc.memory_used);
	if (ok) {
		ws->alloc.memory_used += size;
	} else {
		ws_fail(ws, BQWS_ERR_LIMIT_MAX_MEMORY_USED);
	}

	bqws_mutex_unlock(&ws->alloc.mutex);
	return ok;
}

static void ws_remove_memory_used(bqws_socket *ws, size_t size)
{
	if (size == 0) return;

	// TODO: Atomics
	bqws_mutex_lock(&ws->alloc.mutex);

	bqws_assert(ws->alloc.memory_used >= size);
	ws->alloc.memory_used -= size;

	bqws_mutex_unlock(&ws->alloc.mutex);
}

static void *ws_alloc(bqws_socket *ws, size_t size)
{
	if (!ws_add_memory_used(ws, size)) return NULL;

	void *ptr = allocator_alloc(&ws->allocator, size);
	if (!ptr) ws_fail(ws, BQWS_ERR_ALLOCATOR);

	return ptr;
}

static void *ws_realloc(bqws_socket *ws, void *ptr, size_t old_size, size_t new_size)
{
	if (!ws_add_memory_used(ws, new_size)) return NULL;
	ws_remove_memory_used(ws, old_size);

	void *new_ptr = allocator_realloc(&ws->allocator, ptr, old_size, new_size);
	if (!new_ptr) ws_fail(ws, BQWS_ERR_ALLOCATOR);

	return new_ptr;
}

static void ws_free(bqws_socket *ws, void *ptr, size_t size)
{
	ws_remove_memory_used(ws, size);
	allocator_free(&ws->allocator, ptr, size);
}

static char *ws_copy_str(bqws_socket *ws, const char *str)
{
	size_t len = strlen(str) + 1;
	char *dst = ws_alloc(ws, len);
	if (!dst) return NULL;
	memcpy(dst, str, len);
	return dst;
}

static void ws_free_str(bqws_socket *ws, char *ptr)
{
	if (!ptr) return;
	ws_free(ws, ptr, strlen(ptr) + 1);
}

// Message allocation

static bqws_msg_imp *msg_alloc(bqws_socket *ws, bqws_msg_type type, size_t size)
{
	size_t capacity = size;

	// Space for NULL-terminator
	if (type & BQWS_MSG_TEXT) capacity += 1;

	size_t alloc_size = sizeof(bqws_msg_imp) + capacity;
	bqws_msg_imp *msg = ws_alloc(ws, alloc_size);
	if (!msg) return NULL;

	msg->magic = BQWS_MSG_MAGIC;
	msg->owner = ws;
	msg->allocator = ws->allocator;
	msg->prev = NULL;
	msg->msg.socket = ws;
	msg->msg.type = type;
	msg->msg.size = size;
	msg->msg.capacity = capacity;

	if (type & BQWS_MSG_TEXT) {
		msg->msg.data[size] = '\0';
	}

	return msg;
}

static void msg_release_ownership(bqws_socket *ws, bqws_msg_imp *msg)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	bqws_assert(msg && msg->magic == BQWS_MSG_MAGIC);
	bqws_assert(msg->owner == ws);

	ws_remove_memory_used(ws, msg_alloc_size(&msg->msg));

	msg->owner = NULL;
}

static bool msg_acquire_ownership(bqws_socket *ws, bqws_msg_imp *msg)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	bqws_assert(msg && msg->magic == BQWS_MSG_MAGIC);
	bqws_assert(msg->owner == NULL);

	if (!ws_add_memory_used(ws, msg_alloc_size(&msg->msg))) {
		// We still own the message so need to delete it
		bqws_free_msg(&msg->msg);
		return false;
	}
	msg->owner = ws;

	return true;
}

static void msg_free_owned(bqws_socket *ws, bqws_msg_imp *msg)
{
	if (!msg) return;
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	bqws_assert(msg->magic == BQWS_MSG_MAGIC);
	bqws_assert(msg->owner == ws);

	msg->magic = BQWS_DELETED_MAGIC;
	msg->owner = NULL;

	size_t size = msg_alloc_size(&msg->msg);

	ws_remove_memory_used(ws, size);

	bqws_allocator at = msg->allocator;
	allocator_free(&at, msg, size);
}

static void msg_enqueue(bqws_msg_queue *mq, bqws_msg_imp *msg)
{
	bqws_mutex_lock(&mq->mutex);

	// Adjust the last message to point to `msg` and replace
	// it as the last in the queue
	bqws_assert(msg && msg->magic == BQWS_MSG_MAGIC && msg->prev == NULL);
	if (mq->last) {
		bqws_assert(mq->first);
		bqws_assert(mq->last->magic == BQWS_MSG_MAGIC && mq->last->prev == NULL);
		mq->last->prev = msg;
	} else {
		bqws_assert(!mq->first);
		mq->first = msg;
	}
	mq->last = msg;

	mq->byte_size += msg->msg.size;
	mq->num_messages++;

	mq->total_size += msg->msg.size;
	mq->total_messages++;

	bqws_mutex_unlock(&mq->mutex);
}

static bqws_msg_imp *msg_dequeue(bqws_msg_queue *mq)
{
	bqws_mutex_lock(&mq->mutex);

	bqws_msg_imp *msg = mq->first;

	if (msg) {
		bqws_assert(mq->last);
		bqws_assert(msg->magic == BQWS_MSG_MAGIC);

		bqws_msg_imp *prev = msg->prev;
		msg->prev = NULL;
		mq->first = prev;
		if (prev) {
			bqws_assert(prev->magic == BQWS_MSG_MAGIC);
		} else {
			bqws_assert(mq->last == msg);
			mq->last = NULL;
		}

		bqws_assert(mq->byte_size >= msg->msg.size);
		bqws_assert(mq->num_messages > 0);
		mq->byte_size -= msg->msg.size;
		mq->num_messages--;

	} else {
		bqws_assert(!mq->last);
	}

	bqws_mutex_unlock(&mq->mutex);

	return msg;
}

static void msg_init_queue(bqws_socket *ws, bqws_msg_queue *mq)
{
	bqws_mutex_init(&mq->mutex);
}

static void msg_free_queue(bqws_socket *ws, bqws_msg_queue *mq)
{
	bqws_msg_imp *imp;
	while ((imp = msg_dequeue(mq)) != 0) {
		msg_free_owned(ws, imp);
	}

	bqws_mutex_free(&mq->mutex);
}

static void msg_queue_add_to_total(bqws_msg_queue *mq, size_t size)
{
	bqws_mutex_lock(&mq->mutex);
	mq->total_messages++;
	mq->total_size += size;
	bqws_mutex_unlock(&mq->mutex);
}

static void msg_queue_get_stats(bqws_msg_queue *mq, bqws_io_stats *stats)
{
	bqws_mutex_lock(&mq->mutex);

	stats->total_bytes = mq->total_size;
	stats->total_messages = mq->total_messages;

	stats->queued_bytes = mq->byte_size;
	stats->queued_messages = mq->num_messages;

	bqws_mutex_unlock(&mq->mutex);
}

// Masking

static uint32_t mask_make_key(bqws_socket *ws)
{
	// https://nullprogram.com/blog/2018/07/31/
	uint64_t x = bqws_cpu_time();

	x ^= x >> 32;
	x *= UINT64_C(0xd6e8feb86659fd93);
	x ^= x >> 32;
	x *= UINT64_C(0xd6e8feb86659fd93);
	x ^= x >> 32;

	return (uint32_t)x;
}

static void mask_apply(void *data, size_t size, uint32_t mask)
{
	size_t left = size;

	// Process SIMD width at a time
	char *data_simd = (char*)data;
	#if defined(BQWS_USE_SSE)
	{
		__m128i sse_mask = _mm_set1_epi32(mask);
		while (left >= 16) {
			__m128i w = _mm_loadu_si128((__m128i*)data_simd);
			w = _mm_xor_si128(w, sse_mask);
			_mm_storeu_si128((__m128i*)data_simd, w);
			data_simd += 16;
			left -= 16;
		}
	}
	#endif

	// Process word at a time
	uint32_t *dst32 = (uint32_t*)data_simd;
	while (left >= 4) {
		*dst32++ ^= mask;
		left -= 4;
	}

	// Mask rest
	if (left > 0) {
		bqws_assert(left < 4);
		uint8_t mask_bytes[4];
		memcpy(mask_bytes, &mask, 4);
		uint8_t *dst8 = (uint8_t*)dst32;
		uint8_t *src = mask_bytes;
		while (left > 0) {
			*dst8++ ^= *src++;
			left--;
		}
	}
}

// -- Handshake

static bqws_forceinline bool str_nonempty(const char *s)
{
	return s && *s;
}

static void hs_push_size(bqws_socket *ws, const char *data, size_t size)
{
	if (ws->err) return;

	bqws_assert_locked(&ws->io.mutex);

	if (size > ws->io.handshake.capacity - ws->io.handshake.size) {
		// Grow the buffer geometrically up to `max_handshake_size`
		size_t new_cap = ws->io.handshake.capacity * 2;
		if (new_cap == 0) new_cap = 512;
		if (new_cap > ws->limits.max_handshake_size) new_cap = ws->limits.max_handshake_size;
		if (new_cap == ws->io.handshake.capacity) {
			ws_fail(ws, BQWS_ERR_LIMIT_MAX_HANDSHAKE_SIZE);
			return;
		}

		char *data = ws_realloc(ws, ws->io.handshake.data,	 ws->io.handshake.capacity, new_cap);
		if (!data) return;
		ws->io.handshake.data = data;
		ws->io.handshake.capacity = new_cap;
	}

	memcpy(ws->io.handshake.data + ws->io.handshake.size, data, size);
	ws->io.handshake.size += size;
}

static void hs_push(bqws_socket *ws, const char *a)
{
	hs_push_size(ws, a, strlen(a));
}

static void hs_push2(bqws_socket *ws, const char *a, const char *b)
{
	hs_push(ws, a); hs_push(ws, b);
}

static void hs_push3(bqws_socket *ws, const char *a, const char *b, const char *c)
{
	hs_push(ws, a); hs_push(ws, b); hs_push(ws, c);
}

static void hs_push4(bqws_socket *ws, const char *a, const char *b, const char *c, const char *d)
{
	hs_push(ws, a); hs_push(ws, b); hs_push(ws, c); hs_push(ws, c);
}

static const char *base64_tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static bool hs_to_base64(void *buf, size_t buf_size, const void *data, size_t size)
{
	bqws_assert(size == 0 || data);
	const uint8_t *b = (const uint8_t*)data;

	char *dst = (char*)buf, *end = dst + buf_size;
	ptrdiff_t left = (ptrdiff_t)size;
	while (left > 0) {
		if (end - dst < 5) return false;

		uint32_t a = (uint32_t)b[0] << 16u
			| (left >= 2 ? (uint32_t)b[1] : 0u) << 8u
			| (left >= 3 ? (uint32_t)b[2] : 0u);
		dst[0] = base64_tab[a >> 18];
		dst[1] = base64_tab[(a >> 12) & 0x3f];
		dst[2] = left >= 2 ? base64_tab[(a >> 6) & 0x3f] : '=';
		dst[3] = left >= 3 ? base64_tab[a & 0x3f] : '=';

		dst += 4;
		b += 3;
		left -= 3;
	}

	*dst = '\0';

	return true;
}

static const char *key_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
static void hs_solve_challenge(char dst[32], const char *key_base64)
{
	char challenge[128];
	size_t base64_len = strlen(key_base64);
	size_t guid_len = strlen(key_guid);
	size_t challenge_len = base64_len + guid_len;
	bqws_assert(challenge_len <= sizeof(challenge));
	memcpy(challenge, key_base64, base64_len);
	memcpy(challenge + base64_len, key_guid, guid_len);

	uint8_t digest[20];
	bqws_sha1(digest, challenge, challenge_len);

	bool ret = hs_to_base64(dst, 32, digest, sizeof(digest));
	bqws_assert(ret == true); // 32 bytes should always be enough
}

static void hs_client_handshake(bqws_socket *ws, const bqws_client_opts *opts)
{
	bqws_assert_locked(&ws->io.mutex);

	bqws_assert(!ws->is_server);

	const char *path = str_nonempty(opts->path) ? opts->path : "/";
	hs_push3(ws, "GET ", path, " HTTP/1.1\r\n");

	// Static headers
	hs_push(ws,
		"Connection: Upgrade\r\n"
		"Upgrade: websocket\r\n"
	);

	// User headers
	if (str_nonempty(opts->host)) hs_push3(ws, "Host: ", opts->host, "\r\n");
	if (str_nonempty(opts->origin)) hs_push3(ws, "Origin: ", opts->origin, "\r\n");
	if (opts->num_protocols > 0) {
		hs_push(ws, "Sec-WebSocket-Protocol: ");
		for (size_t i = 0; i < opts->num_protocols; i++) {
			hs_push2(ws, i > 0 ? ", " : "", opts->protocols[i]);
		}
		hs_push(ws, "\r\n");
	}

	// Version (fixed currently, TODO multi-version support)
	hs_push(ws, "Sec-WebSocket-Version: 13\r\n");

	// Random key
	bqws_random_entropy entropy;
	entropy.cpu_time_a = bqws_cpu_time();
	entropy.clock = clock();
	entropy.time = time(NULL);
	entropy.function_pointer = &hs_client_handshake;
	entropy.stack_pointer = &entropy;
	entropy.heap_pointer = ws;
	entropy.cpu_time_b = bqws_cpu_time();

	uint8_t digest[20];
	bqws_sha1(digest, &entropy, sizeof(entropy));

	// We need to retain the key until we have parsed the server handshake
	char *key = ws_alloc(ws, CLIENT_KEY_BASE64_MAX_SIZE);
	if (!key) return;
	ws->io.client_key_base64 = key;

	bool ret = hs_to_base64(key, CLIENT_KEY_BASE64_MAX_SIZE, digest, 16);
	bqws_assert(ret == true); // 32 bytes should always be enough
	hs_push3(ws, "Sec-WebSocket-Key: ", key, "\r\n");

	// Final CRLF
	hs_push(ws, "\r\n");
}


static void hs_server_handshake(bqws_socket *ws)
{
	bqws_assert_locked(&ws->io.mutex);

	bqws_assert(ws->is_server);
	bqws_assert(ws->io.opts_from_client);

	// Fixed header
	hs_push(ws,
		"HTTP/1.1 101 Switching Protocols\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
	);

	// Protocol
	bqws_mutex_lock(&ws->state.mutex);
	const char *protocol = ws->state.chosen_protocol;
	bqws_mutex_unlock(&ws->state.mutex);

	bqws_assert(protocol);
	if (*protocol) {
		hs_push3(ws, "Sec-WebSocket-Protocol: ", protocol, "\r\n");
	}

	// SHA-1 challenge
	char accept[32];
	hs_solve_challenge(accept, ws->io.opts_from_client->random_key_base64);
	hs_push3(ws, "Sec-WebSocket-Accept: ", accept, "\r\n");

	// Final CRLF
	hs_push(ws, "\r\n");

	// Free the handshake state
	ws_free(ws, ws->io.opts_from_client, sizeof(bqws_client_opts));
	ws->io.opts_from_client = NULL;
}

// -- Handshake parsing

static bool hs_parse_literal(bqws_socket *ws, size_t *pos, const char *str)
{
	bqws_assert_locked(&ws->io.mutex);

	size_t len = strlen(str);
	if (ws->io.handshake.size - *pos < len) return false;
	const char *ref = ws->io.handshake.data + *pos;
	if (memcmp(ref, str, len) != 0) return false;
	*pos += len;
	return true;
}

static char *hs_parse_token(bqws_socket *ws, size_t *pos, char end)
{
	bqws_assert_locked(&ws->io.mutex);

	size_t begin = *pos, p = begin;
	while (p != ws->io.handshake.size) {
		char c = ws->io.handshake.data[p];
		if (c == end) {
			ws->io.handshake.data[p] = '\0';
			*pos = p + 1;
			return ws->io.handshake.data + begin;
		}
		if (c == '\r' || c == '\n') return NULL;
		p++;
	}
	return NULL;
}

static void hs_skip_space(bqws_socket *ws, size_t *pos)
{
	bqws_assert_locked(&ws->io.mutex);

	while (*pos < ws->io.handshake.size) {
		char c = ws->io.handshake.data[*pos];
		if (c != ' ' && c != '\t') break;
		++*pos;
	}
}

// Case-insensitive (ASCII) string compare
static bool streq_ic(const char *sa, const char *sb)
{
	for (;;) {
		char a = *sa++, b = *sb++;
		if ((unsigned)(unsigned char)a < 0x80u) a = tolower(a);
		if ((unsigned)(unsigned char)b < 0x80u) b = tolower(b);
		if (a != b) return false;
		if (a == 0) return true;
	}
}

static bool hs_parse_client_handshake(bqws_socket *ws)
{
	bqws_assert_locked(&ws->io.mutex);

	bqws_assert(ws->is_server);
	bqws_assert(!ws->io.opts_from_client);

	size_t pos = 0;

	bqws_client_opts *opts = ws_alloc(ws, sizeof(bqws_client_opts));
	if (!opts) return false;
	memset(opts, 0, sizeof(bqws_client_opts));
	ws->io.opts_from_client = opts;

	// GET /path HTTP/1.1
	if (!hs_parse_literal(ws, &pos, "GET")) return false;
	hs_skip_space(ws, &pos);
	opts->path = hs_parse_token(ws, &pos, ' ');
	if (!opts->path) return false;
	hs_skip_space(ws, &pos);
	if (!hs_parse_literal(ws, &pos, "HTTP/1.1\r\n")) return false;

	// Headers
	while (!hs_parse_literal(ws, &pos, "\r\n")) {
		if (opts->num_headers >= BQWS_MAX_HEADERS) {
			ws_fail(ws, BQWS_ERR_TOO_MANY_HEADERS);
			return false;
		}

		bqws_header *header = &opts->headers[opts->num_headers];
		header->name = hs_parse_token(ws, &pos, ':');
		hs_skip_space(ws, &pos);

		size_t value_pos = pos;
		header->value = hs_parse_token(ws, &pos, '\r');
		if (!header->name || !header->value) return false;
		if (!hs_parse_literal(ws, &pos, "\n")) return false;

		if (streq_ic(header->name, "Host")) {
			opts->host = header->value;
			opts->num_headers++;
		} else if (streq_ic(header->name, "Origin")) {
			opts->origin = header->value;
			opts->num_headers++;
		} else if (streq_ic(header->name, "Sec-Websocket-Protocol")) {
			size_t cur_pos = pos;

			// Parse protocols
			pos = value_pos;
			while (pos < cur_pos) {
				// Either token ',' or final token that is zero-terminated
				// already since it's the last thing in `header->value`.
				char *protocol = hs_parse_token(ws, &pos, ',');
				hs_skip_space(ws, &pos);
				if (!protocol) {
					protocol = ws->io.handshake.data + pos;
					pos = cur_pos;
				}

				if (opts->num_protocols >= BQWS_MAX_PROTOCOLS) {
					ws_fail(ws, BQWS_ERR_TOO_MANY_PROTOCOLS);
					return false;
				}
				opts->protocols[opts->num_protocols++] = protocol;
			}

			pos = cur_pos;
		} else if (streq_ic(header->name, "Sec-Websocket-Key")) {
			size_t len = strlen(header->value) + 1;
			if (len > sizeof(opts->random_key_base64)) {
				ws_fail(ws, BQWS_ERR_HEADER_KEY_TOO_LONG);
				return false;
			}
			memcpy(opts->random_key_base64, header->value, len);
		} else if (streq_ic(header->name, "Sec-Websocket-Version")) {
			// TODO: Version negotiatoin
			if (strcmp(header->value, "13") != 0) {
				ws_fail(ws, BQWS_ERR_UNSUPPORTED_VERSION);
				return false;
			}
		} else {
			opts->num_headers++;
		}
	}

	// Store the end of the parsed header in case we read past the
	// header in the beginning.
	ws->io.handshake.read_offset = pos;

	if (!opts->host) opts->host = "";
	if (!opts->origin) opts->origin = "";

	return true;
}

static bool hs_parse_server_handshake(bqws_socket *ws)
{
	bqws_assert_locked(&ws->io.mutex);

	bqws_assert(!ws->is_server);
	bqws_assert(ws->io.client_key_base64);

	size_t pos = 0;

	// HTTP/1.1 101 Switching Protocols
	if (!hs_parse_literal(ws, &pos, "HTTP/1.1 101")) return false;
	hs_parse_token(ws, &pos, '\r'); // Skip description
	if (!hs_parse_literal(ws, &pos, "\n")) return false;

	// Headers
	while (!hs_parse_literal(ws, &pos, "\r\n")) {
		// TODO: Keep headers?

		bqws_header header;
		header.name = hs_parse_token(ws, &pos, ':');
		hs_skip_space(ws, &pos);

		size_t value_pos = pos;
		header.value = hs_parse_token(ws, &pos, '\r');
		if (!header.name || !header.value) return false;
		if (!hs_parse_literal(ws, &pos, "\n")) return false;

		if (streq_ic(header.name, "Sec-Websocket-Accept")) {

			// Check the SHA of the challenge
			char reference[32];
			hs_solve_challenge(reference, ws->io.client_key_base64);
			if (strcmp(header.value, reference) != 0) {
				ws_fail(ws, BQWS_ERR_HEADER_BAD_ACCEPT);
				return false;
			}

			// Free the client key
			ws_free(ws, ws->io.client_key_base64, CLIENT_KEY_BASE64_MAX_SIZE);
			ws->io.client_key_base64 = NULL;

		} else if (streq_ic(header.name, "Sec-Websocket-Protocol")) {
			// Protocol that the server chose

			// Keep the first one if there's duplicates
			if (!ws->state.chosen_protocol) {
				char *copy = ws_copy_str(ws, header.value);

				bqws_mutex_lock(&ws->state.mutex);
				if (!ws->state.chosen_protocol) {
					ws->state.chosen_protocol = copy;
				} else {
					ws_free_str(ws, copy);
				}
				bqws_mutex_unlock(&ws->state.mutex);
			}
		}
	}

	// Store the end of the parsed header in case we read past the
	// header in the beginning.
	ws->io.handshake.read_offset = pos;

	// If the server didn't choose any protocol set it as ""
	if (!ws->state.chosen_protocol) {
		char *copy = ws_copy_str(ws, "");

		bqws_mutex_lock(&ws->state.mutex);
		if (!ws->state.chosen_protocol) {
			ws->state.chosen_protocol = copy;
		} else {
			ws_free_str(ws, copy);
		}
		bqws_mutex_unlock(&ws->state.mutex);
	}

	return true;
}

static void hs_finish_handshake(bqws_socket *ws)
{
	bqws_assert_locked(&ws->io.mutex);

	if (ws->err) return;

	ws_log(ws, "State: OPEN");

	bqws_mutex_lock(&ws->state.mutex);
	ws->state.state = BQWS_STATE_OPEN;
	bqws_mutex_unlock(&ws->state.mutex);

	// Free the handshake buffer
	ws_free(ws, ws->io.handshake.data, ws->io.handshake.capacity);
	ws->io.handshake.data = NULL;
	ws->io.handshake.size = 0;
	ws->io.handshake.capacity = 0;

	// Notify IO that the connection is open
	if (ws->user_io.notify_fn) {
		ws->user_io.notify_fn(ws->user_io.user, ws);
	}
}

static void hs_store_handshake_overflow(bqws_socket *ws)
{
	bqws_assert_locked(&ws->io.mutex);

	size_t offset = ws->io.handshake.read_offset;
	size_t left = ws->io.handshake.size - offset;
	if (left == 0) return;

	ws->io.handshake_overflow.data = ws_alloc(ws, left);
	if (!ws->io.handshake_overflow.data) return;
	memcpy(ws->io.handshake_overflow.data, ws->io.handshake.data + offset, left);
	ws->io.handshake_overflow.capacity = left;
	ws->io.handshake_overflow.size = left;
}

// Control messages

static void ws_enqueue_send(bqws_socket *ws, bqws_msg_imp *msg)
{
	if (ws->user_io.notify_fn) {
		ws->user_io.notify_fn(ws->user_io.user, ws);
	}

	msg_enqueue(&ws->send_queue, msg);
}

static void ws_enqueue_recv(bqws_socket *ws, bqws_msg_imp *msg)
{
	size_t msg_memory_size = msg_alloc_size(&msg->msg);

	// If the user callback returns true the message won't be
	// enqueued to the receive queue.
	if (ws->message_fn) {
		msg_release_ownership(ws, msg);
		if (ws->message_fn(ws->message_user, ws, &msg->msg)) {
			// Message was consumed and won't be processed so add
			// it to the total count
			msg_queue_add_to_total(&ws->recv_queue, msg->msg.size);
		}
		if (!msg_acquire_ownership(ws, msg)) return;
	}

	msg_enqueue(&ws->recv_queue, msg);
}

static void ws_handle_control(bqws_socket *ws, bqws_msg_imp *msg)
{
	bqws_msg_type type = msg->msg.type;
	bqws_msg_imp *msg_to_enqueue = msg;

	if (type == BQWS_MSG_CONTROL_CLOSE) {

		bqws_mutex_lock(&ws->state.mutex);

		// Set peer close reason from the message
		if (msg->msg.size >= 2) {
			ws->state.peer_reason = (bqws_close_reason)(
				((uint32_t)(uint8_t)msg->msg.data[0] << 8) |
				((uint32_t)(uint8_t)msg->msg.data[1] << 0) );
		} else {
			ws->state.peer_reason = BQWS_CLOSE_NO_REASON;
		}

		// Set unknown error if the connection was closed with an error
		if (ws->state.peer_reason != BQWS_CLOSE_NORMAL && ws->state.peer_reason != BQWS_CLOSE_GOING_AWAY) {
			ws->state.peer_err = BQWS_ERR_UNKNOWN;
		}

		// Potentially patch bqws-specific info
		if (msg->msg.size == sizeof(bqws_err_close_data)) {
			bqws_err_close_data *data = (bqws_err_close_data*)msg->msg.data;
			if (!memcmp(data->magic, "BQWS", 4)) {
				ws->state.peer_err = (bqws_error)(
					((uint32_t)(uint8_t)data->error_be[0] << 24) |
					((uint32_t)(uint8_t)data->error_be[1] << 16) |
					((uint32_t)(uint8_t)data->error_be[2] <<  8) |
					((uint32_t)(uint8_t)data->error_be[3] <<  0) );
			}
		}

		// Echo the close message back
		if (!ws->state.close_to_send) {
			ws->state.close_to_send = msg;

			// Don't free the message as it will be re-sent
			msg = NULL;
		}

		// Peer has closed connection so we go directly to CLOSED
		if (ws->state.state == BQWS_STATE_OPEN) {
			ws_log(ws, "State: CLOSING (received Close from peer)");
			ws->state.start_closing_ts = bqws_get_timestamp();
			ws->state.state = BQWS_STATE_CLOSING;
		}

		ws->state.stop_read = true;
		ws->state.close_received = true;
		if (ws->state.close_sent) {
			ws_close(ws);
		}

		bqws_mutex_unlock(&ws->state.mutex);

	} else if (type == BQWS_MSG_CONTROL_PING) {
		if (ws->recv_control_messages) {
			// We want to re-use the PING message to send it back
			// so we need to copy it for receiving
			bqws_msg_imp *copy = msg_alloc(ws, type, msg->msg.size);
			if (!copy) return;
			memcpy(copy->msg.data, msg->msg.data, msg->msg.size);
			msg_to_enqueue = copy;
		}

		// Turn the PING message into a PONG
		msg->msg.type = BQWS_MSG_CONTROL_PONG;

		bqws_mutex_lock(&ws->state.mutex);

		// Only retain the latest PONG to send back
		if (ws->state.pong_to_send) {
			msg_free_owned(ws, ws->state.pong_to_send);
		}
		ws->state.pong_to_send = msg;

		bqws_mutex_unlock(&ws->state.mutex);

		// Don't free the message as it will be re-sent
		msg = NULL;

	} else if (type == BQWS_MSG_CONTROL_PONG) {
		// PONG messages don't require any kind of handling
	} else {
		bqws_assert(0 && "Unexpected control message");
	}

	// Receive control messages
	if (ws->recv_control_messages) {
		ws_enqueue_recv(ws, msg_to_enqueue);
	} else if (msg) {
		msg_free_owned(ws, msg);
	}
}

// Input / output

// Read data into a buffer, returns amount of bytes used read.
// Returns 0 and sets `ws->err` if parsing fails.

static size_t ws_recv_from_handshake_overflow(void *user, bqws_socket *ws, void *data, size_t max_size, size_t min_size)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	bqws_assert_locked(&ws->io.mutex);

	size_t offset = ws->io.handshake_overflow.read_offset;
	size_t left = ws->io.handshake_overflow.size - offset;
	size_t to_copy = max_size;
	if (to_copy > left) to_copy = left;
	memcpy(data, ws->io.handshake_overflow.data + offset, to_copy);
	ws->io.handshake_overflow.read_offset += to_copy;
	return to_copy;
}

static bool ws_read_handshake(bqws_socket *ws, bqws_io_recv_fn recv_fn, void *user)
{
	bqws_assert_locked(&ws->io.mutex);

	for (;;) {
		if (ws->io.handshake.size == ws->io.handshake.capacity) {
			// Grow the buffer geometrically up to `max_handshake_size`
			size_t new_cap = ws->io.handshake.capacity * 2;
			if (new_cap == 0) new_cap = 512;
			if (new_cap > ws->limits.max_handshake_size) new_cap = ws->limits.max_handshake_size;
			if (new_cap == ws->io.handshake.capacity) {
				ws_fail(ws, BQWS_ERR_LIMIT_MAX_HANDSHAKE_SIZE);
				return false;
			}

			char *data = ws_realloc(ws, ws->io.handshake.data,	 ws->io.handshake.capacity, new_cap);
			if (!data) return false;
			ws->io.handshake.data = data;
			ws->io.handshake.capacity = new_cap;
		}

		// TODO: min_size can be up to 4 depending on the suffix of the buffer

		// Read some data
		size_t to_read = ws->io.handshake.capacity - ws->io.handshake.size;
		size_t num_read = recv_fn(user, ws, ws->io.handshake.data + ws->io.handshake.size, to_read, 1);
		if (num_read == 0) return false;
		if (num_read == SIZE_MAX) {
			ws_fail(ws, BQWS_ERR_IO_READ);
			return false;
		}
		bqws_assert(num_read <= to_read);
		ws->io.handshake.size += num_read;

		// Scan for \r\n\r\n
		ptrdiff_t begin = (ptrdiff_t)ws->io.handshake.size - num_read - 4;
		if (begin < 0) begin = 0;
		char *ptr = ws->io.handshake.data + begin;
		char *end = ws->io.handshake.data + ws->io.handshake.size;
		while ((ptr = memchr(ptr, '\r', end - ptr)) != NULL) {
			if (end - ptr >= 4 && !memcmp(ptr, "\r\n\r\n", 4)) {
				return true;
			} else {
				ptr++;
			}
		}

		if (num_read != to_read) break;
	}

	return false;
}

static bool ws_read_data(bqws_socket *ws, bqws_io_recv_fn recv_fn, void *user)
{
	bqws_assert_locked(&ws->io.mutex);
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);

	bqws_msg_buffer *buf = &ws->io.recv_buf;

	bqws_state state;

	bqws_mutex_lock(&ws->state.mutex);
	if (ws->state.stop_read) {
		bqws_mutex_unlock(&ws->state.mutex);
		return false;
	}
	state = ws->state.state;
	bqws_mutex_unlock(&ws->state.mutex);

	if (state == BQWS_STATE_CONNECTING) {

		if (ws->is_server) {
			// Server: read the client handshake first, after it's done wait for
			// `ws_write_data()` to set `ws->state == BQWS_STATE_OPEN`
			if (!ws->io.client_handshake_done) {
				// Read the client handshake
				if (ws_read_handshake(ws, recv_fn, user)) {
					if (!hs_parse_client_handshake(ws)) {
						ws_fail(ws, BQWS_ERR_HEADER_PARSE);
						return false;
					}
					ws->io.client_handshake_done = true;

					// Re-use the handshake buffer for the response, but copy
					// remaining data to be read later
					hs_store_handshake_overflow(ws);
					ws->io.handshake.size = 0;

					// Notify IO that there is a handshake to send
					if (ws->user_io.notify_fn) {
						ws->user_io.notify_fn(ws->user_io.user, ws);
					}
				}
			}

			// Wait that the response is sent
			return false;
		} else {
			// Client: Send the request first before trying to read the response
			if (!ws->io.client_handshake_done) return false;
			if (!ws_read_handshake(ws, recv_fn, user)) return false;

			if (!hs_parse_server_handshake(ws)) {
				ws_fail(ws, BQWS_ERR_HEADER_PARSE);
				return false;
			}

			// Store remaining data before deleting the handshake
			hs_store_handshake_overflow(ws);

			// Client handshake is done!
			hs_finish_handshake(ws);
		}
	}

	// If there's still data in the handshake buffer empty it before
	// reading any new data
	if (ws->io.handshake_overflow.data && recv_fn != &ws_recv_from_handshake_overflow) {

		// Read from the handshake until we reach the end
		while (!ws->err && ws->io.handshake_overflow.read_offset < ws->io.handshake_overflow.size) {
			ws_read_data(ws, &ws_recv_from_handshake_overflow, NULL);
		}

		if (ws->err) return false;

		// Free the handshake
		ws_free(ws, ws->io.handshake_overflow.data, ws->io.handshake_overflow.capacity);
		ws->io.handshake_overflow.data = NULL;
		ws->io.handshake_overflow.size = 0;
		ws->io.handshake_overflow.capacity = 0;

		// Continue with reading from the actual data source
	}

	// Header has not been parsed yet
	if (!buf->msg) {

		// Check if we can fit a new message to the receive queue
		if (ws->recv_queue.num_messages >= ws->limits.max_recv_queue_messages
			|| ws->recv_queue.byte_size >= ws->limits.max_recv_queue_size) {
			return false;
		}

		// We need to read at least two bytes to determine
		// the header size
		if (buf->header_size == 0) {
			if (buf->header_offset < 2) {
				size_t to_read = sizeof(ws->io.recv_header) - buf->header_offset;
				size_t min_read = 2 - buf->header_offset;
				size_t num_read = recv_fn(user, ws, ws->io.recv_header + buf->header_offset, to_read, min_read);
				if (num_read == 0) return false;
				if (num_read == SIZE_MAX) {
					ws_fail(ws, BQWS_ERR_IO_READ);
					return false;
				}
				bqws_assert(num_read <= to_read);
				buf->header_offset += num_read;

				if (ws->ping_interval != SIZE_MAX) {
					ws->io.last_read_ts = bqws_get_timestamp();
				}
			}

			if (buf->header_offset < 2) return false;

			uint8_t mask_len = ws->io.recv_header[1];
			uint32_t len = mask_len & 0x7f;

			// Minimum header size
			size_t header_size = 2;

			// MASK bit set: contains 32-bit mask field
			if (mask_len & 0x80) header_size += 4; 

			// 16/64-bit message length
			if (len == 126) header_size += 2;
			else if (len == 127) header_size += 8;

			buf->header_size = header_size;
			bqws_assert(buf->header_size <= sizeof(ws->io.recv_header));
		}

		// Read more header data if we need it
		if (buf->header_offset < buf->header_size) {
			size_t to_read = sizeof(ws->io.recv_header) - buf->header_offset;
			size_t min_read = buf->header_size - buf->header_offset;
			size_t num_read = recv_fn(user, ws, ws->io.recv_header + buf->header_offset, to_read, min_read);
			if (num_read == 0) return false;
			if (num_read == SIZE_MAX) {
				ws_fail(ws, BQWS_ERR_IO_READ);
				return false;
			}
			bqws_assert(num_read <= to_read);
			buf->header_offset += num_read;

			if (ws->ping_interval != SIZE_MAX) {
				ws->io.last_read_ts = bqws_get_timestamp();
			}

			return false;
		}

		if (buf->header_offset < buf->header_size) return false;

		// Parse the header and allocate the message
		const uint8_t *h = (const uint8_t*)ws->io.recv_header;

		// Static header bits
		bool fin = (h[0] & 0x80) != 0;
		if (h[0] & 0x70) {
			// Reserved bits RSV1-3
			ws_fail(ws, BQWS_ERR_RESERVED_BIT);
			return false;
		}
		uint32_t opcode = (uint32_t)(h[0] & 0x0f);
		uint32_t mask = (uint32_t)(h[1] & 0x80) != 0;
		uint64_t payload_length = (uint64_t)(h[1] & 0x7f);
		h += 2;

		// Extended length: Read 2 or 8 bytes of big
		// endian payload length.
		size_t payload_ext = 0;
		if (payload_length == 126) {
			payload_ext = 2;
			payload_length = 0;
		} else if (payload_length == 127) {
			payload_ext = 8;
			payload_length = 0;
		}
		for (size_t i = 0; i < payload_ext; i++) {
			size_t shift = (payload_ext - i - 1) * 8;
			payload_length |= (uint64_t)h[i] << shift;
		}
		h += payload_ext;

		// Check the payload length and cast to `size_t`
		if (payload_length > (uint64_t)ws->limits.max_recv_msg_size) {
			ws_fail(ws, BQWS_ERR_LIMIT_MAX_RECV_MSG_SIZE);
			return false;
		}
		size_t msg_size = (size_t)payload_length;

		// Masking key
		buf->masked = mask;
		if (mask) {
			memcpy(&buf->mask_key, h, 4);
			h += 4;
		}

		bqws_assert((const char*)h - ws->io.recv_header == buf->header_size);

		bqws_msg_type type = BQWS_MSG_INVALID;

		// Resolve the type of the message
		if (opcode == 0x0) {
			// Continuation frame

			if (buf->partial_type == BQWS_MSG_INVALID) {
				// Continuation frame without a prior partial frame
				ws_fail(ws, BQWS_ERR_BAD_CONTINUATION);
				return false;
			}

			type = buf->partial_type | BQWS_MSG_PARTIAL_BIT;
			if (fin) {
				type |= BQWS_MSG_FINAL_BIT;
				buf->partial_type = BQWS_MSG_INVALID;
			}

		} else if (opcode == 0x1 || opcode == 0x2) {
			// Text or Binary
			type = opcode == 0x1 ? BQWS_MSG_TEXT : BQWS_MSG_BINARY;
			if (!fin) {
				if (buf->partial_type != BQWS_MSG_INVALID) {
					// New partial message even though one is already
					// being sent
					ws_fail(ws, BQWS_ERR_UNFINISHED_PARTIAL);
					return false;
				}

				buf->partial_type = type;
				type |= BQWS_MSG_PARTIAL_BIT;
			}
		} else if (opcode >= 0x8 && opcode <= 0xa) {
			// Control frames
			if      (opcode == 0x8) type = BQWS_MSG_CONTROL_CLOSE;
			else if (opcode == 0x9) type = BQWS_MSG_CONTROL_PING;
			else if (opcode == 0xa) type = BQWS_MSG_CONTROL_PONG;

			if (!fin) {
				// Control frames may not be fragmented
				ws_fail(ws, BQWS_ERR_PARTIAL_CONTROL);
				return false;
			}
		} else {
			// Unsupported opcode
			ws_fail(ws, BQWS_ERR_BAD_OPCODE);
			return false;
		}
		bqws_assert(type != BQWS_MSG_INVALID);

		// All good, allocate the message
		bqws_msg_imp *imp = msg_alloc(ws, type, msg_size);
		if (!imp) return false;

		buf->msg = imp;
		buf->offset = 0;

		// Copy rest of the header bytes to the message
		size_t offset = buf->header_size;
		size_t left = buf->header_offset - offset;
		if (left > 0) {
			size_t to_copy = left;
			if (to_copy > imp->msg.size) to_copy = imp->msg.size;
			memcpy(imp->msg.data, ws->io.recv_header + offset, to_copy);
			buf->offset += to_copy;
			offset += to_copy;
			left -= to_copy;
		}

		// If there's still some data shift it as the next header
		if (left > 0) {
			memmove(ws->io.recv_header, ws->io.recv_header + offset, left);
		}
		buf->header_offset = left;
	}

	bqws_msg_imp *msg = buf->msg;

	// Read message data if the message is not empty
	bqws_assert(buf->offset <= msg->msg.size);
	if (msg->msg.size > 0 && buf->offset < msg->msg.size) {

		size_t to_read = msg->msg.size - buf->offset;
		size_t num_read = recv_fn(user, ws, msg->msg.data + buf->offset, to_read, to_read);
		if (num_read == 0) return false;
		if (num_read == SIZE_MAX) {
			ws_fail(ws, BQWS_ERR_IO_READ);
			return false;
		}
		bqws_assert(num_read <= to_read);

		if (ws->ping_interval != SIZE_MAX) {
			ws->io.last_read_ts = bqws_get_timestamp();
		}

		buf->offset += num_read;
		if (num_read < to_read) return false;
	}

	if (buf->masked) {
		mask_apply(msg->msg.data, msg->msg.size, buf->mask_key);
	}

	bqws_assert(buf->offset == msg->msg.size);

	// Peek at all incoming messages before processing
	if (ws->peek_fn) {
		ws->peek_fn(ws->peek_user, ws, &msg->msg, true);
	}

	// If we copied the last bytes of the message we can push it
	// to the queue and clear the buffer.
	bqws_msg_type type = msg->msg.type;

	if (ws->log_recv) {
		ws_log2(ws, "Received: ", bqws_msg_type_str(buf->msg->msg.type));
	}

	if ((type & BQWS_MSG_PARTIAL_BIT) != 0 && !ws->recv_partial_messages) {

		// Only allow partial messages that combine up to the maximum message size
		bqws_assert(msg->msg.size <= ws->limits.max_recv_msg_size);
		if (ws->io.recv_partial_size >= ws->limits.max_recv_msg_size - msg->msg.size) {
			ws_fail(ws, BQWS_ERR_LIMIT_MAX_RECV_MSG_SIZE);
			return false;
		}

		ws->io.recv_partial_size += msg->msg.size;

		// If we dont expose partial messages collect them to `recv_partial_queue`.
		if (type & BQWS_MSG_FINAL_BIT) {
			// If this is the final message concatenate all the partial messages
			// in the queue and enqueue the final one>

			bqws_msg_type base_type = msg->msg.type & BQWS_MSG_TYPE_MASK;
			bqws_msg_imp *combined = msg_alloc(ws, base_type, ws->io.recv_partial_size);
			if (!combined) return false;

			size_t offset = 0;

			// `recv_queue` with this message as the last part.
			bqws_msg_imp *part;
			while ((part = msg_dequeue(&ws->recv_partial_queue)) != NULL) {
				bqws_assert(part->magic == BQWS_MSG_MAGIC);
				bqws_assert((part->msg.type & BQWS_MSG_TYPE_MASK) == base_type);

				memcpy(combined->msg.data + offset, part->msg.data, part->msg.size);
				offset += part->msg.size;

				// Delete the part
				msg_free_owned(ws, part);
			}

			// Final part
			memcpy(combined->msg.data + offset, msg->msg.data, msg->msg.size);
			offset += msg->msg.size;
			msg_free_owned(ws, msg);

			bqws_assert(offset == combined->msg.size);

			ws_enqueue_recv(ws, combined);

			// Clear the partial total size
			ws->io.recv_partial_size = 0;
		} else {

			if (ws->recv_partial_queue.num_messages >= ws->limits.max_partial_message_parts) {
				ws_fail(ws, BQWS_ERR_LIMIT_MAX_PARTIAL_MESSAGE_PARTS);
				return false;
			}

			msg_enqueue(&ws->recv_partial_queue, msg);
		}

	} else {
		if (type & BQWS_MSG_CONTROL_MASK) {
			// Control message, handle it. `ws_handle_control()` enqueues the
			// message to `recv_queue` internally if required.
			ws_handle_control(ws, msg);
		} else {
			// Non-partial data message
			ws_enqueue_recv(ws, msg);
		}
	}
	buf->offset = 0;
	buf->header_size = 0;
	buf->msg = NULL;

	return true;
}

static bool ws_write_handshake(bqws_socket *ws, bqws_io_send_fn *send_fn, void *user)
{
	bqws_assert_locked(&ws->io.mutex);

	size_t to_send = ws->io.handshake.size - ws->io.handshake.write_offset;
	size_t sent = send_fn(user, ws, ws->io.handshake.data + ws->io.handshake.write_offset, to_send);
	if (sent == SIZE_MAX) {
		ws_fail(ws, BQWS_ERR_IO_WRITE);
		return false;
	}

	bqws_assert(sent <= to_send);
	ws->io.handshake.write_offset += sent;
	return sent == to_send;
}

static bool ws_write_data(bqws_socket *ws, bqws_io_send_fn *send_fn, void *user)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	bqws_assert_locked(&ws->io.mutex);

	bqws_msg_buffer *buf = &ws->io.send_buf;

	bqws_state state;
	char *protocol;

	bqws_mutex_lock(&ws->state.mutex);
	if (ws->state.stop_write) {
		bqws_mutex_unlock(&ws->state.mutex);
		return false;
	}
	state = ws->state.state;
	protocol = ws->state.chosen_protocol;
	bqws_mutex_unlock(&ws->state.mutex);

	if (state == BQWS_STATE_CONNECTING) {

		if (ws->is_server) {
			// Server: read the client handshake first
			if (!ws->io.client_handshake_done) return false;

			// Wait for the user to accept/reject the connection
			if (!protocol) return false;

			// Write the server handshake on demand
			if (ws->io.handshake.size == 0) {
				hs_server_handshake(ws);
				if (ws->err) return false;
			}

			// Write the server handshake
			if (!ws_write_handshake(ws, send_fn, user)) return false;

			// Server handshake is done!
			hs_finish_handshake(ws);

		} else {
			// Client: Send the request and always wait for response
			if (!ws->io.client_handshake_done) {
				if (!ws_write_handshake(ws, send_fn, user)) return false;

				// Re-use the handshake buffer for the response, 
				ws->io.handshake.size = 0;
				ws->io.client_handshake_done = true;
			}

			return false;
		}
	}

	if (!buf->msg) {
		// No message: Send high priority messages first.

		bqws_mutex_lock(&ws->state.mutex);

		if (ws->state.close_to_send && !ws->state.close_sent) {
			// First priority: Send close message
			buf->msg = ws->state.close_to_send;
			ws->state.close_to_send = NULL;
			bqws_assert(buf->msg->msg.type == BQWS_MSG_CONTROL_CLOSE);
		} else if (ws->state.state != BQWS_STATE_OPEN) {
			// Stop sending anything if the state is not open
		} else if (ws->state.pong_to_send) {
			// Try to respond to PING messages fast
			buf->msg = ws->state.pong_to_send;
			ws->state.pong_to_send = NULL;
			bqws_assert(buf->msg->msg.type == BQWS_MSG_CONTROL_PONG);
		} else {
			// Send user message if there is one
			buf->msg = msg_dequeue(&ws->send_queue);
		}

		bqws_mutex_unlock(&ws->state.mutex);

		// Did not find any message
		if (!buf->msg) return false;

		bqws_assert(buf->msg && buf->msg->magic == BQWS_MSG_MAGIC);

	}
	bqws_msg_imp *msg = buf->msg;
	bqws_assert(msg && msg->magic == BQWS_MSG_MAGIC);

	// Re-assign the public socket to be this one for the callback
	msg->msg.socket = ws;

	// Peek at all outgoing messages before processing
	if (ws->peek_fn) {
		ws->peek_fn(ws->peek_user, ws, &msg->msg, false);
	}

	if (ws->send_message_fn) {
		msg_release_ownership(ws, msg);
		if (ws->send_message_fn(ws->send_message_user, ws, &msg->msg)) {
			if (ws->log_send) {
				ws_log2(ws, "Direct send: ", bqws_msg_type_str(msg->msg.type));
			}
			buf->msg = NULL;
			return true;
		} else {
			msg_acquire_ownership(ws, msg);
			return false;
		}
	}

	if (ws->ping_interval != SIZE_MAX) {
		ws->io.last_write_ts = bqws_get_timestamp();
	}

	if (buf->header_size == 0) {
		bqws_msg_type type = msg->msg.type;
		bool mask = ws->is_server ? ws->mask_server : !ws->unsafe_dont_mask_client;
		bool fin = true;
		uint32_t opcode = ~0u;

		if (type & BQWS_MSG_TYPE_MASK) {
			bqws_msg_type base_type = type & BQWS_MSG_TYPE_MASK;
			opcode = base_type == BQWS_MSG_TEXT ? 0x1 : 0x2;

			if (type & BQWS_MSG_PARTIAL_BIT) {
				if (buf->partial_type != BQWS_MSG_INVALID) {
					// Partial continuation
					bqws_assert(buf->partial_type == base_type);
					opcode = 0x0;
				}

				if (type & BQWS_MSG_FINAL_BIT) {
					// This can be either the end of a partial message
					// or just a single-part partial message.
					buf->partial_type = BQWS_MSG_INVALID;
				} else {
					// Partial begin or continuation
					buf->partial_type = base_type;
					fin = false;
				}
			}

		} else if (type & BQWS_MSG_CONTROL_MASK) {
			// Control message
			if (type == BQWS_MSG_CONTROL_CLOSE)     opcode = 0x8;
			else if (type == BQWS_MSG_CONTROL_PING) opcode = 0x9;
			else if (type == BQWS_MSG_CONTROL_PONG) opcode = 0xa;
		} else {
			bqws_assert(0 && "Trying to send non-data non-control message");
		}

		bqws_assert(opcode != ~0u);

		// Use the smallest payload length representation
		size_t payload_ext = 0;
		size_t payload_len = msg->msg.size;
		if (payload_len > 65535u) {
			payload_len = 127;
			payload_ext = 8;
		} else if (payload_len > 125) {
			payload_len = 126;
			payload_ext = 2;
		}

		uint8_t *h = (uint8_t*)ws->io.send_header;
		// Static header bits
		h[0] = (fin ? 0x80 : 0x0) | (uint8_t)opcode;
		h[1] = (mask ? 0x80 : 0x0) | (uint8_t)payload_len;
		h += 2;

		// Extended length: Read 2 or 8 bytes of big
		// endian payload length.
		for (size_t i = 0; i < payload_ext; i++) {
			size_t shift = (payload_ext - i - 1) * 8;
			h[i] = (uint8_t)((uint64_t)msg->msg.size >> shift);
		}
		h += payload_ext;

		// Masking key
		buf->masked = mask;
		if (mask) {
			uint32_t mask_key = mask_make_key(ws);
			buf->mask_key = mask_key;
			memcpy(h, &buf->mask_key, 4);
			h += 4;

			// Apply the mask
			mask_apply(msg->msg.data, msg->msg.size, mask_key);
		}

		buf->header_size = (char*)h - ws->io.send_header;
		bqws_assert(buf->header_size <= sizeof(ws->io.send_header));
	}

	// Send the header
	if (buf->header_offset < buf->header_size) {
		size_t to_send = buf->header_size - buf->header_offset;
		size_t sent = send_fn(user, ws, ws->io.send_header + buf->header_offset, to_send);
		if (sent == SIZE_MAX) {
			ws_fail(ws, BQWS_ERR_IO_WRITE);
			return false;
		}
		bqws_assert(sent <= to_send);
		buf->header_offset += sent;
		if (sent < to_send) return false;
	}

	// Send the message
	{
		size_t to_send = msg->msg.size - buf->offset;
		size_t sent = send_fn(user, ws, msg->msg.data + buf->offset, to_send);
		if (sent == SIZE_MAX) {
			ws_fail(ws, BQWS_ERR_IO_WRITE);
			return false;
		}
		bqws_assert(sent <= to_send);
		buf->offset += sent;
		if (sent < to_send) return false;
	}

	if (ws->log_send) {
		ws_log2(ws, "Sent: ", bqws_msg_type_str(buf->msg->msg.type));
	}

	// Mark close as been sent
	if (msg->msg.type == BQWS_MSG_CONTROL_CLOSE) {
		bqws_mutex_lock(&ws->state.mutex);
		if (ws->state.state == BQWS_STATE_OPEN) {
			ws_log(ws, "State: CLOSING (queued user close)");
			ws->state.state = BQWS_STATE_CLOSING;
			ws->state.start_closing_ts = bqws_get_timestamp();
		}
		ws->state.close_sent = true;
		if (ws->state.close_received) {
			ws_close(ws);
		}
		bqws_mutex_unlock(&ws->state.mutex);
	}

	// Delete the message
	msg_free_owned(ws, msg);

	// Sent everything, clear status
	buf->offset = 0;
	buf->header_offset = 0;
	buf->header_size = 0;
	buf->msg = NULL;
	return true;
}

// WebSocket initialization

static char *verify_filter_str(bqws_verify_filter *f, size_t *offset, const char *str)
{
	if (!str) return NULL;
	size_t len = strlen(str) + 1;
	char *dst = f->text_data + *offset;
	memcpy(dst, str, len);
	*offset += len;
	return dst;
}

static void bqws_internal_filter_verify(void *user, bqws_socket *ws, const bqws_client_opts *opts)
{
	bqws_verify_filter *f = (bqws_verify_filter*)user;
	bool ok = true;

	// Check common headers
	ok = ok && (!f->path || !strcmp(f->path, opts->path));
	ok = ok && (!f->host || streq_ic(f->host, opts->host));
	ok = ok && (!f->origin || streq_ic(f->origin, opts->origin));

	const char *protocol = NULL;
	if (f->num_protocols > 0) {
		// If the fitler has protocols try to find one
		// O(n^2) but bounded by BQWS_MAX_PROTOCOLS
		for (size_t ci = 0; ci < opts->num_protocols && !protocol; ci++) {
			for (size_t fi = 0; fi < f->num_protocols; fi++) {
				if (!strcmp(f->protocols[fi], opts->protocols[ci])) {
					protocol = f->protocols[fi];
					break;
				}
			}
		}
		ok = ok && protocol != NULL;
	} else {
		// If not don't use any protocol name
		protocol = "";
	}

	if (ok) {
		bqws_assert(protocol != NULL);
		bqws_server_accept(ws, protocol);
	} else {
		bqws_server_reject(ws);
	}
}

static void ws_expand_default_limits(bqws_limits *limits)
{
#define WS_DEFAULT(p_name, p_value) if (!limits->p_name) limits->p_name = p_value

	WS_DEFAULT(max_memory_used, 262144);
	WS_DEFAULT(max_recv_msg_size, 262144);
	WS_DEFAULT(max_handshake_size, 262144);
	WS_DEFAULT(max_recv_queue_messages, 1024);
	WS_DEFAULT(max_recv_queue_size, 262144);
	WS_DEFAULT(max_partial_message_parts, 16384);

#undef WS_DEFAULT
}

static bqws_socket *ws_new_socket(const bqws_opts *opts, bool is_server)
{
	bqws_opts null_opts;
	if (!opts) {
		memset(&null_opts, 0, sizeof(null_opts));
		opts = &null_opts;
	}

	bqws_socket *ws = (bqws_socket*)allocator_alloc(&opts->allocator, sizeof(bqws_socket) + opts->user_size);
	if (!ws) return NULL;

	memset(ws, 0, sizeof(bqws_socket));
	ws->magic = BQWS_SOCKET_MAGIC;
	ws->is_server = is_server;
	ws->allocator = opts->allocator;
	ws->user_io = opts->io;
	ws->limits = opts->limits;
	ws->recv_partial_messages = opts->recv_partial_messages;
	ws->recv_control_messages = opts->recv_control_messages;
	ws->mask_server = opts->mask_server;
	ws->message_fn = opts->message_fn;
	ws->message_user = opts->message_user;
	ws->peek_fn = opts->peek_fn;
	ws->peek_user = opts->peek_user;
	ws->log_fn = opts->log_fn;
	ws->log_user = opts->log_user;
	ws->log_send = opts->log_send;
	ws->log_recv = opts->log_recv;
	ws->send_message_fn = opts->send_message_fn;
	ws->send_message_user = opts->send_message_user;
	ws->user_size = opts->user_size;

	ws_expand_default_limits(&ws->limits);

	bqws_mutex_init(&ws->err_mutex);
	bqws_mutex_init(&ws->state.mutex);
	bqws_mutex_init(&ws->io.mutex);
	bqws_mutex_init(&ws->alloc.mutex);
	bqws_mutex_init(&ws->partial.mutex);

	msg_init_queue(ws, &ws->recv_queue);
	msg_init_queue(ws, &ws->recv_partial_queue);
	msg_init_queue(ws, &ws->send_queue);

	if (opts->ping_interval) {
		ws->ping_interval = opts->ping_interval;
	} else {
		ws->ping_interval = is_server ? 20000 : 10000;
	}

	ws->close_timeout = opts->close_timeout ? opts->close_timeout : 5000;
	ws->ping_response_timeout = opts->ping_response_timeout ? opts->ping_response_timeout : 4 * ws->ping_interval;

	bqws_assert(ws->ping_interval > 0);
	if (ws->ping_interval != SIZE_MAX) {
		bqws_timestamp ts = bqws_get_timestamp();
		ws->io.last_write_ts = ts;
		ws->io.last_read_ts = ts;
		ws->io.last_ping_ts = ts;
	}

	// Copy or zero-init user data
	if (opts->user_size > 0) {
		if (opts->user_data) {
			memcpy(ws->user_data, opts->user_data, opts->user_size);
		} else {
			memset(ws->user_data, 0, opts->user_size);
		}
	}

	if (opts->name) ws->name = ws_copy_str(ws, opts->name);

	if (opts->skip_handshake) {
		ws_log(ws, "State: OPEN (skip handhake)");
		ws->state.state = BQWS_STATE_OPEN;
	} else {
		ws_log(ws, "State: CONNECTING");
		ws->state.state = BQWS_STATE_CONNECTING;
	}

	if (ws->err) {
		bqws_free_socket(ws);
		return NULL;
	}

	return ws;
}

// -- API

bqws_socket *bqws_new_client(const bqws_opts *opts, const bqws_client_opts *client_opts)
{
	bqws_socket *ws = ws_new_socket(opts, false);
	if (!ws) return NULL;

	// Setup client handshake immediately if the socket is not open already
	if (ws->state.state == BQWS_STATE_CONNECTING) {
		bqws_client_opts null_opts;
		if (!client_opts) {
			memset(&null_opts, 0, sizeof(null_opts));
			client_opts = &null_opts;
		}

		bqws_mutex_lock(&ws->io.mutex);
		hs_client_handshake(ws, client_opts);
		bqws_mutex_unlock(&ws->io.mutex);

		// Notify IO that there's a client handshake to send
		if (ws->user_io.notify_fn) {
			ws->user_io.notify_fn(ws->user_io.user, ws);
		}
	}

	return ws;
}

bqws_socket *bqws_new_server(const bqws_opts *opts, const bqws_server_opts *server_opts)
{
	bqws_socket *ws = ws_new_socket(opts, true);
	if (!ws) return NULL;

	{
		bqws_server_opts null_opts;
		if (!server_opts) {
			memset(&null_opts, 0, sizeof(null_opts));
			server_opts = &null_opts;
		}

		ws->verify_fn = server_opts->verify_fn;
		ws->verify_user = server_opts->verify_user;

		// Setup automatic verify filter if needed
		if (server_opts->verify_filter && !ws->verify_fn) {
			bqws_client_opts *filter = server_opts->verify_filter;
			size_t text_size = 0;

			text_size += filter->path ? strlen(filter->path) + 1 : 0;
			text_size += filter->host ? strlen(filter->host) + 1 : 0;
			text_size += filter->origin ? strlen(filter->origin) + 1 : 0;
			for (size_t i = 0; i < filter->num_protocols; i++) {
				bqws_assert(filter->protocols[i] && *filter->protocols[i]);
				text_size += strlen(filter->protocols[i]) + 1;
			}

			bqws_verify_filter *copy = ws_alloc(ws, sizeof(bqws_verify_filter) + text_size);
			if (!copy) {
				bqws_free_socket(ws);
				return NULL;
			}

			memset(copy, 0, sizeof(bqws_verify_filter));
			copy->magic = BQWS_FILTER_MAGIC;
			copy->text_size = text_size;
			size_t offset = 0;

			copy->path = verify_filter_str(copy, &offset, filter->path);
			copy->host = verify_filter_str(copy, &offset, filter->host);
			copy->origin = verify_filter_str(copy, &offset, filter->origin);
			copy->num_protocols = filter->num_protocols;
			for (size_t i = 0; i < filter->num_protocols; i++) {
				copy->protocols[i] = verify_filter_str(copy, &offset, filter->protocols[i]);
			}

			bqws_assert(offset == text_size);

			ws->verify_fn = &bqws_internal_filter_verify;
			ws->verify_user = copy;
		}
	}

	return ws;
}

void bqws_close(bqws_socket *ws, bqws_close_reason reason, const void *data, size_t size)
{
	if (ws->err) return;

	bqws_mutex_lock(&ws->state.mutex);

	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	bqws_assert(size == 0 || data);
	if (ws->state.close_to_send || ws->state.state >= BQWS_STATE_CLOSING) {
		bqws_mutex_unlock(&ws->state.mutex);
		return;
	}

	bqws_msg_imp *imp = msg_alloc(ws, BQWS_MSG_CONTROL_CLOSE, size + 2);
	if (imp) {
		imp->msg.data[0] = (uint8_t)(reason >> 8);
		imp->msg.data[1] = (uint8_t)(reason & 0xff);
		memcpy(imp->msg.data + 2, data, size);

		ws->state.close_to_send = imp;
		ws->state.start_closing_ts = bqws_get_timestamp();
		ws->state.state = BQWS_STATE_CLOSING;

		ws_log(ws, "State: CLOSING (user close)");
	}

	bqws_mutex_unlock(&ws->state.mutex);
}

void bqws_queue_close(bqws_socket *ws, bqws_close_reason reason, const void *data, size_t size)
{
	if (ws->err) return;

	bqws_mutex_lock(&ws->state.mutex);

	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	bqws_assert(size == 0 || data);
	if (ws->state.close_to_send || ws->state.state >= BQWS_STATE_CLOSING) {
		bqws_mutex_unlock(&ws->state.mutex);
		return;
	}

	bqws_msg_imp *imp = msg_alloc(ws, BQWS_MSG_CONTROL_CLOSE, size + 2);
	if (imp) {
		imp->msg.data[0] = (uint8_t)(reason >> 8);
		imp->msg.data[1] = (uint8_t)(reason & 0xff);
		memcpy(imp->msg.data + 2, data, size);
		ws_enqueue_send(ws, imp);
	}

	bqws_mutex_unlock(&ws->state.mutex);
}

void bqws_free_socket(bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);

	if (ws->user_io.close_fn && !ws->state.io_closed) {
		ws->user_io.close_fn(ws->user_io.user, ws);
	}

	ws_log(ws, "Freed");

	// Free everything, as the socket may have errored it can
	// be in almost any state

	// Mutexes
	bqws_mutex_free(&ws->err_mutex);
	bqws_mutex_free(&ws->state.mutex);
	bqws_mutex_free(&ws->io.mutex);
	bqws_mutex_free(&ws->alloc.mutex);
	bqws_mutex_free(&ws->partial.mutex);

	// Pending messages
	msg_free_queue(ws, &ws->recv_queue);
	msg_free_queue(ws, &ws->recv_partial_queue);
	msg_free_queue(ws, &ws->send_queue);
	if (ws->state.pong_to_send) msg_free_owned(ws, ws->state.pong_to_send);
	if (ws->state.close_to_send) msg_free_owned(ws, ws->state.close_to_send);

	// Read/write buffers
	ws_free(ws, ws->io.handshake.data, ws->io.handshake.capacity);
	ws_free(ws, ws->io.handshake_overflow.data, ws->io.handshake_overflow.capacity);
	if (ws->io.recv_buf.msg) msg_free_owned(ws, ws->io.recv_buf.msg);
	if (ws->io.send_buf.msg) msg_free_owned(ws, ws->io.send_buf.msg);
	if (ws->partial.next_partial_to_send) msg_free_owned(ws, ws->partial.next_partial_to_send);

	// Misc buffers
	if (ws->io.client_key_base64) ws_free(ws, ws->io.client_key_base64, CLIENT_KEY_BASE64_MAX_SIZE);
	if (ws->io.opts_from_client) ws_free(ws, ws->io.opts_from_client, sizeof(bqws_client_opts));

	// String copies
	ws_free_str(ws, ws->state.chosen_protocol);
	ws_free_str(ws, ws->name);

	// Verify filter copy
	if (ws->verify_fn == &bqws_internal_filter_verify) {
		bqws_verify_filter *filter = ws->verify_user;
		bqws_assert(filter->magic == BQWS_FILTER_MAGIC);
		filter->magic = BQWS_DELETED_MAGIC;
		ws_free(ws, filter, sizeof(bqws_verify_filter) + filter->text_size);
	}

	bqws_assert(ws->alloc.memory_used == 0);

	ws->magic = BQWS_DELETED_MAGIC;

	bqws_allocator at = ws->allocator;
	allocator_free(&at, ws, sizeof(bqws_socket) + ws->user_size);
}

bqws_client_opts *bqws_server_get_client_opts(bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	bqws_assert(ws->is_server);
	bqws_assert(ws->state.state == BQWS_STATE_CONNECTING);

	bqws_mutex_lock(&ws->io.mutex);
	bqws_client_opts *opts = ws->io.opts_from_client;
	bqws_mutex_unlock(&ws->io.mutex);

	return opts;
}

void bqws_server_accept(bqws_socket *ws, const char *protocol)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	bqws_assert(ws->is_server);
	bqws_assert(ws->state.state == BQWS_STATE_CONNECTING);
	if (ws->err) return;

	// Use emtpy string to differentiate from not set
	if (!protocol) protocol = "";

	bqws_mutex_lock(&ws->state.mutex);
	if (!ws->state.chosen_protocol) {
		ws->state.chosen_protocol = ws_copy_str(ws, protocol);
	}
	bqws_mutex_unlock(&ws->state.mutex);
}

void bqws_server_reject(bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	bqws_assert(ws->is_server);

	ws_fail(ws, BQWS_ERR_SERVER_REJECT);
}

bqws_state bqws_get_state(const bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	// No mutex! We can always underestimate the state
	bqws_state state = ws->state.state;
	bqws_state override_state = ws->state.override_state;
	if (override_state > state) state = override_state;
	return state;
}

bqws_error bqws_get_error(const bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	return ws->err;
}

bool bqws_is_closed(const bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	// No mutex! We can always underestimate the state
	bqws_state state = ws->state.state;
	bqws_state override_state = ws->state.override_state;
	if (override_state > state) state = override_state;
	return state == BQWS_STATE_CLOSED;
}

size_t bqws_get_memory_used(const bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	// No mutex! This doesn't need to be accurate
	return ws->alloc.memory_used;
}

bool bqws_is_server(const bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	return ws->is_server;
}

void *bqws_user_data(const bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	return (void*)ws->user_data;
}

size_t bqws_user_data_size(const bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	return ws->user_size;
}

const char *bqws_get_name(const bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	return ws->name;
}

bqws_stats bqws_get_stats(const bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);

	bqws_stats stats;
	msg_queue_get_stats((bqws_msg_queue*)&ws->recv_queue, &stats.recv);
	msg_queue_get_stats((bqws_msg_queue*)&ws->send_queue, &stats.send);
	return stats;
}

void *bqws_get_io_user(const bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);

	return ws->user_io.user;
}

bqws_limits bqws_get_limits(const bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	return ws->limits;
}

void bqws_set_limits(bqws_socket *ws, const bqws_limits *limits)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	bqws_assert(limits);

	bqws_limits copy = *limits;
	ws_expand_default_limits(&copy);
	ws->limits = copy;
}

bqws_close_reason bqws_get_peer_close_reason(const bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);

	bqws_mutex_lock((bqws_mutex*)&ws->state.mutex);
	bqws_close_reason reason = ws->state.peer_reason;
	bqws_mutex_unlock((bqws_mutex*)&ws->state.mutex);

	return reason;
}

bqws_error bqws_get_peer_error(const bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);

	bqws_mutex_lock((bqws_mutex*)&ws->state.mutex);
	bqws_error err = ws->state.peer_err;
	bqws_mutex_unlock((bqws_mutex*)&ws->state.mutex);

	return err;
}

const char *bqws_get_protocol(const bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);

	// TODO: Cache this pointer outside of IO mutex
	bqws_mutex_lock((bqws_mutex*)&ws->state.mutex);
	const char *protocol = ws->state.chosen_protocol;
	bqws_mutex_unlock((bqws_mutex*)&ws->state.mutex);

	return protocol;
}

bqws_msg *bqws_recv(bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	if (ws->err) return NULL;

	// Messages are re-combined in `recv_queue` if
	// `recv_partial_messages` is disabled.

	bqws_msg_imp *imp = msg_dequeue(&ws->recv_queue);
	if (!imp) return NULL;
	bqws_assert(imp->magic == BQWS_MSG_MAGIC);

	msg_release_ownership(ws, imp);
	return &imp->msg;
}

void bqws_free_msg(bqws_msg *msg)
{
	if (!msg) return;

	bqws_msg_imp *imp = msg_imp(msg);
	bqws_assert(imp->magic == BQWS_MSG_MAGIC);
	bqws_assert(imp->owner == NULL);

	imp->magic = BQWS_DELETED_MAGIC;

	bqws_allocator at = imp->allocator;
	allocator_free(&at, imp, msg_alloc_size(msg));
}

void bqws_send(bqws_socket *ws, bqws_msg_type type, const void *data, size_t size)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	bqws_assert((type & BQWS_MSG_PARTIAL_BIT) == 0);
	if (ws->err) return;
	bqws_assert(size == 0 || data);

	bqws_msg_imp *imp = msg_alloc(ws, type, size);
	if (!imp) return;

	memcpy(imp->msg.data, data, size);
	ws_enqueue_send(ws, imp);
}

void bqws_send_binary(bqws_socket *ws, const void *data, size_t size)
{
	bqws_send(ws, BQWS_MSG_BINARY, data, size);
}

void bqws_send_text(bqws_socket *ws, const char *str)
{
	bqws_assert(str);
	bqws_send(ws, BQWS_MSG_TEXT, str, strlen(str));
}

void bqws_send_text_len(bqws_socket *ws, const void *str, size_t len)
{
	bqws_send(ws, BQWS_MSG_TEXT, str, len);
}

bqws_msg *bqws_allocate_msg(bqws_socket *ws, bqws_msg_type type, size_t size)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	if (ws->err) return NULL;

	bqws_msg_imp *imp = msg_alloc(ws, type, size);
	if (!imp) return NULL;

	msg_release_ownership(ws, imp);
	return &imp->msg;
}

void bqws_send_msg(bqws_socket *ws, bqws_msg *msg)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	bqws_assert(msg && msg->type == BQWS_MSG_TEXT || msg->type == BQWS_MSG_BINARY);
	bqws_assert(msg->size <= msg->capacity);

	bqws_msg_imp *imp = msg_imp(msg);
	bqws_assert(imp->magic == BQWS_MSG_MAGIC);

	if (ws->err) return;

	if (!msg_acquire_ownership(ws, imp)) return;

	ws_enqueue_send(ws, imp);
}

void bqws_send_begin(bqws_socket *ws, bqws_msg_type type)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	bqws_assert(type == BQWS_MSG_TEXT || type == BQWS_MSG_BINARY);
	if (ws->err) return;

	bqws_mutex_lock(&ws->partial.mutex);

	bqws_assert(ws->partial.send_partial_type == BQWS_MSG_INVALID);
	bqws_assert(ws->partial.next_partial_to_send == NULL);

	ws->partial.send_partial_type = type;

	bqws_mutex_unlock(&ws->partial.mutex);
}

void bqws_send_append(bqws_socket *ws, const void *data, size_t size)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	if (ws->err) return;

	bqws_mutex_lock(&ws->partial.mutex);

	bqws_assert(ws->partial.send_partial_type != BQWS_MSG_INVALID);

	if (ws->partial.next_partial_to_send) {
		bqws_assert(ws->partial.next_partial_to_send->magic == BQWS_MSG_MAGIC);
		ws_enqueue_send(ws, ws->partial.next_partial_to_send);
	}

	bqws_msg_type partial_type = ws->partial.send_partial_type | BQWS_MSG_PARTIAL_BIT;
	bqws_msg_imp *imp = msg_alloc(ws, partial_type, size);
	if (imp) {
		memcpy(imp->msg.data, data, size);
		ws->partial.next_partial_to_send = imp;
	}

	bqws_mutex_unlock(&ws->partial.mutex);
}

void bqws_send_append_str(bqws_socket *ws, const void *str)
{
	bqws_send_append(ws, str, strlen(str));
}

void bqws_send_append_msg(bqws_socket *ws, bqws_msg *msg)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	bqws_assert(msg->type == BQWS_MSG_TEXT || msg->type == BQWS_MSG_BINARY);
	if (ws->err) return;

	bqws_mutex_lock(&ws->partial.mutex);

	bqws_assert(ws->partial.send_partial_type != BQWS_MSG_INVALID);
	bqws_assert((ws->partial.send_partial_type & BQWS_MSG_TYPE_MASK) == msg->type);

	if (ws->partial.next_partial_to_send) {
		bqws_assert(ws->partial.next_partial_to_send->magic == BQWS_MSG_MAGIC);
		ws_enqueue_send(ws, ws->partial.next_partial_to_send);
	}

	bqws_msg_imp *imp = msg_imp(msg);
	if (!msg_acquire_ownership(ws, imp)) return;

	msg->type = ws->partial.send_partial_type | BQWS_MSG_PARTIAL_BIT;
	ws->partial.next_partial_to_send = imp;

	bqws_mutex_unlock(&ws->partial.mutex);
}

void bqws_send_finish(bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	if (ws->err) return;

	bqws_mutex_lock(&ws->partial.mutex);

	bqws_assert(ws->partial.send_partial_type != BQWS_MSG_INVALID);

	if (ws->partial.next_partial_to_send) {
		bqws_assert(ws->partial.next_partial_to_send->magic == BQWS_MSG_MAGIC);
		ws->partial.next_partial_to_send->msg.type |= BQWS_MSG_FINAL_BIT;
		ws_enqueue_send(ws, ws->partial.next_partial_to_send);
		ws->partial.next_partial_to_send = NULL;
	}

	ws->partial.send_partial_type = BQWS_MSG_INVALID;

	bqws_mutex_unlock(&ws->partial.mutex);
}

void bqws_send_ping(bqws_socket *ws, const void *data, size_t size)
{
	bqws_send(ws, BQWS_MSG_CONTROL_PING, data, size);
}

void bqws_send_pong(bqws_socket *ws, const void *data, size_t size)
{
	bqws_send(ws, BQWS_MSG_CONTROL_PONG, data, size);
}

void bqws_update(bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	if (ws->err) return;

	bqws_update_state(ws);
	bqws_update_io(ws);
}

void bqws_update_state(bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	if (ws->err) return;

	bqws_mutex_lock(&ws->state.mutex);
	bqws_state state = ws->state.state;
	char *protocol = ws->state.chosen_protocol;
	bqws_timestamp start_closing_ts = ws->state.start_closing_ts;
	bqws_mutex_unlock(&ws->state.mutex);

	bqws_mutex_lock(&ws->io.mutex);

	if (state == BQWS_STATE_CONNECTING) {

		// If we're connecting but haven't set a protocol and the user
		// has provided a verify function or filter run it here.
		if (ws->io.client_handshake_done && !protocol && ws->verify_fn) {
			bqws_assert(ws->is_server);
			bqws_assert(ws->io.opts_from_client);
			ws->verify_fn(ws->verify_user, ws, ws->io.opts_from_client);
		}

	} else if (state == BQWS_STATE_OPEN) {

		// Automatic PING send
		if (ws->ping_interval != SIZE_MAX) {
			bqws_timestamp time = bqws_get_timestamp();
			size_t delta_read = bqws_timestamp_delta_to_ms(ws->io.last_read_ts, time);
			size_t delta_ping = bqws_timestamp_delta_to_ms(ws->io.last_ping_ts, time);
			size_t delta_write = bqws_timestamp_delta_to_ms(ws->io.last_write_ts, time);

			size_t delta = delta_read >= delta_write ? delta_read : delta_write;
			size_t delta_from_ping = delta <= delta_ping ? delta : delta_ping;

			if (delta_from_ping > ws->ping_interval) {
				ws->io.last_ping_ts = time;
				// Maybe send PONG only?
				bqws_send_ping(ws, NULL, 0);
			}

			if (ws->ping_response_timeout != SIZE_MAX) {
				if (delta >= ws->ping_response_timeout) {
					ws_fail(ws, BQWS_ERR_PING_TIMEOUT);

					bqws_mutex_lock(&ws->state.mutex);
					ws_close(ws);
					bqws_mutex_unlock(&ws->state.mutex);
				}
			}
		}

	} else if (state == BQWS_STATE_CLOSING) {

		// Close timeout
		if (ws->close_timeout != SIZE_MAX) {
			bqws_timestamp time = bqws_get_timestamp();
			size_t delta = bqws_timestamp_delta_to_ms(start_closing_ts, time);
			if (delta > ws->close_timeout) {
				ws_fail(ws, BQWS_ERR_CLOSE_TIMEOUT);

				bqws_mutex_lock(&ws->state.mutex);
				ws_close(ws);
				bqws_mutex_unlock(&ws->state.mutex);
			}
		}

	}

	bqws_mutex_unlock(&ws->io.mutex);
}

void bqws_update_io(bqws_socket *ws)
{
	bqws_update_io_write(ws);
	bqws_update_io_read(ws);
}

void bqws_update_io_read(bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	if (ws->err) return;

	bool do_read = true;

	bqws_mutex_lock(&ws->io.mutex);

	// If read and write are stopped close the IO
	bqws_mutex_lock(&ws->state.mutex);
	if (ws->state.stop_read && ws->state.stop_write) {
		if (ws->user_io.close_fn && !ws->state.io_closed) {
			ws->user_io.close_fn(ws->user_io.user, ws);
			ws->state.io_closed = true;
		}
	}
	do_read = !ws->state.stop_read;
	bqws_mutex_unlock(&ws->state.mutex);

	// TODO: Throttle reads
	if (do_read) {
		if (ws->user_io.recv_fn) {
			while (ws_read_data(ws, ws->user_io.recv_fn, ws->user_io.user)) {
				// Keep reading as long as there is space
			}
		}
	}

	bqws_mutex_unlock(&ws->io.mutex);
}

void bqws_update_io_write(bqws_socket *ws)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	if (ws->err) return;

	bool do_write = true;

	bqws_mutex_lock(&ws->io.mutex);

	// If read and write are stopped close the IO
	bqws_mutex_lock(&ws->state.mutex);
	if (ws->state.stop_read && ws->state.stop_write) {
		if (ws->user_io.close_fn && !ws->state.io_closed) {
			ws->user_io.close_fn(ws->user_io.user, ws);
			ws->state.io_closed = true;
		}
	}
	do_write = !ws->state.stop_write;
	bqws_mutex_unlock(&ws->state.mutex);

	if (do_write) {
		if (ws->user_io.send_fn) {
			while (ws_write_data(ws, ws->user_io.send_fn, ws->user_io.user)) {
				// Keep writing as long as there is space
			}
		}

		if (ws->user_io.flush_fn) {
			if (!ws->user_io.flush_fn(ws->user_io.user, ws)) {
				ws_fail(ws, BQWS_ERR_IO_WRITE);
			}
		}
	}

	bqws_mutex_unlock(&ws->io.mutex);
}

size_t bqws_read_from(bqws_socket *ws, const void *data, size_t size)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	bqws_assert(!ws->user_io.recv_fn);

	bqws_mutex_lock(&ws->io.mutex);

	bqws_mem_stream s;
	s.ptr = (char*)data;
	s.end = s.ptr + size;

	while (ws_read_data(ws, &mem_stream_recv, &s)) {
		// Keep reading as long as there is space
	}

	bqws_mutex_unlock(&ws->io.mutex);

	return s.ptr - (char*)data;
}

size_t bqws_write_to(bqws_socket *ws, void *data, size_t size)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	bqws_assert(!ws->user_io.send_fn);

	bqws_mutex_lock(&ws->io.mutex);

	bqws_mem_stream s;
	s.ptr = (char*)data;
	s.end = s.ptr + size;

	while (ws_write_data(ws, &mem_stream_send, &s)) {
		// Keep writing as long as there is space
	}

	if (ws->user_io.flush_fn) {
		if (!ws->user_io.flush_fn(ws->user_io.user, ws)) {
			ws_fail(ws, BQWS_ERR_IO_WRITE);
		}
	}

	bqws_mutex_unlock(&ws->io.mutex);

	return s.ptr - (char*)data;
}

void bqws_direct_push_msg(bqws_socket *ws, bqws_msg *msg)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);
	bqws_assert(msg && msg->size <= msg->capacity);

	bqws_msg_imp *imp = msg_imp(msg);
	bqws_assert(imp->magic == BQWS_MSG_MAGIC);

	if (ws->err) return;

	if (!msg_acquire_ownership(ws, imp)) return;

	if (ws->log_recv) {
		ws_log2(ws, "Direct recv: ", bqws_msg_type_str(msg->type));
	}

	ws_enqueue_recv(ws, imp);
}

void bqws_direct_set_override_state(bqws_socket *ws, bqws_state state)
{
	bqws_assert(ws && ws->magic == BQWS_SOCKET_MAGIC);

	ws_log2(ws, "Override state: ", bqws_state_str(state));

	bqws_mutex_lock(&ws->state.mutex);
	ws->state.override_state = state;
	bqws_mutex_unlock(&ws->state.mutex);
}

bool bqws_parse_url(bqws_url *url, const char *str)
{
	// Format [wss://][host.example.com][:1234][/path]

	const char *scheme = str;
	const char *scheme_end = strstr(scheme, "://");
	const char *host = scheme_end ? scheme_end + 3 : scheme;
	const char *port_start = host;
	if (*host == '[') {
		// Skip IPv6 address
		port_start = strstr(host, "]");
	}
	const char *port = strstr(port_start, ":");
	const char *path = strstr(port_start, "/");
	if (!path) path = port_start + strlen(port_start);
	if (port && port > path) port = NULL;
	const char *host_end = port ? port : path;

	size_t scheme_len = scheme_end - scheme;
	size_t host_len = host_end - host;
	if (scheme_len >= sizeof(url->scheme)) return false;
	if (host_len >= sizeof(url->host)) return false;

	bool secure = scheme_len == 3 && !memcmp(scheme, "wss", 3);

	int port_num;
	if (port) {
		char *port_end;
		port_num = (int)strtol(port + 1, &port_end, 10);
		if (port_end != path) return false;
		if (port_num < 0 || port_num > UINT16_MAX) return false;
		port_num = (uint16_t)port_num;
	} else {
		port_num = secure ? 443 : 80;
	}

	// vv No fails below, no writes above ^^

	url->port = (uint16_t)port_num;

	memcpy(url->scheme, scheme, scheme_len);
	url->scheme[scheme_len] = '\0';

	memcpy(url->host, host, host_len);
	url->host[host_len] = '\0';

	url->path = *path ? path : "/";

	url->secure = secure;

	return true;
}

const char *bqws_error_str(bqws_error error)
{
	switch (error) {
	case BQWS_OK: return "OK";
	case BQWS_ERR_UNKNOWN: return "UNKNOWN";
	case BQWS_ERR_SERVER_REJECT: return "SERVER_REJECT";
	case BQWS_ERR_LIMIT_MAX_MEMORY_USED: return "LIMIT_MAX_MEMORY_USED";
	case BQWS_ERR_LIMIT_MAX_RECV_MSG_SIZE: return "LIMIT_MAX_RECV_MSG_SIZE";
	case BQWS_ERR_LIMIT_MAX_HANDSHAKE_SIZE: return "LIMIT_MAX_HANDSHAKE_SIZE";
	case BQWS_ERR_LIMIT_MAX_PARTIAL_MESSAGE_PARTS: return "LIMIT_MAX_PARTIAL_MESSAGE_PARTS";
	case BQWS_ERR_PING_TIMEOUT: return "BQWS_ERR_PING_TIMEOUT";
	case BQWS_ERR_CLOSE_TIMEOUT: return "BQWS_ERR_CLOSE_TIMEOUT";
	case BQWS_ERR_ALLOCATOR: return "ALLOCATOR";
	case BQWS_ERR_BAD_CONTINUATION: return "BAD_CONTINUATION";
	case BQWS_ERR_UNFINISHED_PARTIAL: return "UNFINISHED_PARTIAL";
	case BQWS_ERR_PARTIAL_CONTROL: return "PARTIAL_CONTROL";
	case BQWS_ERR_BAD_OPCODE: return "BAD_OPCODE";
	case BQWS_ERR_RESERVED_BIT: return "RESERVED_BIT";
	case BQWS_ERR_IO_WRITE: return "IO_WRITE";
	case BQWS_ERR_IO_READ: return "IO_READ";
	case BQWS_ERR_BAD_HANDSHAKE: return "BAD_HANDSHAKE";
	case BQWS_ERR_UNSUPPORTED_VERSION: return "UNSUPPORTED_VERSION";
	case BQWS_ERR_TOO_MANY_HEADERS: return "TOO_MANY_HEADERS";
	case BQWS_ERR_TOO_MANY_PROTOCOLS: return "TOO_MANY_PROTOCOLS";
	case BQWS_ERR_HEADER_KEY_TOO_LONG: return "HEADER_KEY_TOO_LONG";
	case BQWS_ERR_HEADER_BAD_ACCEPT: return "HEADER_BAD_ACCEPT";
	case BQWS_ERR_HEADER_PARSE: return "HEADER_PARSE";
	default: return "(unknown)";
	}
}

const char *bqws_msg_type_str(bqws_msg_type type)
{
	switch (type) {
	case BQWS_MSG_TEXT: return "TEXT";
	case BQWS_MSG_BINARY: return "BINARY";
	case BQWS_MSG_PARTIAL_TEXT: return "PARTIAL_TEXT";
	case BQWS_MSG_PARTIAL_BINARY: return "PARTIAL_BINARY";
	case BQWS_MSG_FINAL_TEXT: return "FINAL_TEXT";
	case BQWS_MSG_FINAL_BINARY: return "FINAL_BINARY";
	case BQWS_MSG_CONTROL_CLOSE: return "CONTROL_CLOSE";
	case BQWS_MSG_CONTROL_PING: return "CONTROL_PING";
	case BQWS_MSG_CONTROL_PONG: return "CONTROL_PONG";
	default: return "(unknown)";
	}
}

const char *bqws_state_str(bqws_state state)
{
	switch (state) {
	case BQWS_STATE_INVALID: return "INVALID";
	case BQWS_STATE_CONNECTING: return "CONNECTING";
	case BQWS_STATE_OPEN: return "OPEN";
	case BQWS_STATE_CLOSING: return "CLOSING";
	case BQWS_STATE_CLOSED: return "CLOSED";
	default: return "(unknown)";
	}
}

// TODO: Add define for this

/* ================ sha1.c ================ */
/*
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain
Test Vectors (from FIPS PUB 180-1)
"abc"
  A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D
"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1
A million repetitions of "a"
  34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F
*/

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);

/* Hash a single 512-bit block. This is the core of the algorithm. */

static void SHA1Transform(uint32_t state[5], const void *buffer)
{
	uint32_t a, b, c, d, e;
	typedef union {
		unsigned char c[64];
		uint32_t l[16];
	} CHAR64LONG16;
	CHAR64LONG16 block_buf, *block = &block_buf;
	memcpy(block, buffer, 64);
    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

/* SHA1Init - Initialize new context */

static void SHA1Init(SHA1_CTX* context)
{
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}

/* Run your data through this. */

static void SHA1Update(SHA1_CTX* context, const void* data, uint32_t len)
{
	uint32_t i, j;
	const char *bytes = (const char *)data;

    j = context->count[0];
    if ((context->count[0] += len << 3) < j)
	context->count[1]++;
    context->count[1] += (len>>29);
    j = (j >> 3) & 63;
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64-j));
        SHA1Transform(context->state, context->buffer);
        for ( ; i + 63 < len; i += 64) {
            SHA1Transform(context->state, &bytes[i]);
        }
        j = 0;
    }
    else i = 0;
    memcpy(&context->buffer[j], &bytes[i], len - i);
}


/* Add padding and return the message digest. */

static void SHA1Final(unsigned char digest[20], SHA1_CTX* context)
{
	unsigned i;
	unsigned char finalcount[8];
	unsigned char c;

    for (i = 0; i < 8; i++) {
        finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)]
         >> ((3-(i & 3)) * 8) ) & 255);  /* Endian independent */
    }
    c = 0200;
    SHA1Update(context, &c, 1);
    while ((context->count[0] & 504) != 448) {
	c = 0000;
        SHA1Update(context, &c, 1);
    }
    SHA1Update(context, finalcount, 8);  /* Should cause a SHA1Transform() */
    for (i = 0; i < 20; i++) {
        digest[i] = (unsigned char)
         ((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
    }
}
/* ================ end of sha1.c ================ */

static void bqws_sha1(uint8_t digest[20], const void *data, size_t size)
{
	SHA1_CTX ctx;
	SHA1Init(&ctx);
	SHA1Update(&ctx, data, (uint32_t)size);
	SHA1Final((unsigned char*)digest, &ctx);
}
