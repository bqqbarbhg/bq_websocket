#include "bq_websocket_platform.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#if 0

#if defined(_WIN32)

#include <WinSock2.h>
#include <WS2tcpip.h>

#define _WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define BQWS_PT_USE_OPENSSL 1

#ifndef BQWS_PT_USE_OPENSSL
#define BQWS_PT_USE_OPENSSL 0
#endif

#if BQWS_PT_USE_OPENSSL
	#include <openssl/ssl.h>
#endif

#pragma comment(lib, "ws2_32.lib")

typedef struct {
	SOCKET s;
	size_t send_size;
	char send_buf[512];

#if BQWS_PT_USE_OPENSSL
	struct {
		bool connected;
		SSL *ssl;
		BIO *bio;
	} ssl;
#endif

} pt_io;

#if BQWS_PT_USE_OPENSSL
typedef struct {
	SSL_CTX *ctx;
} pt_ssl;
static pt_ssl g_ssl;
#endif

struct bqws_pt_server {
	SOCKET s;
	bool secure;
};

static bool pt_init(const bqws_pt_init_opts *opts)
{
	WSADATA data;
	WSAStartup(MAKEWORD(2,2), &data);
	int res;

	#if BQWS_PT_USE_OPENSSL
	{
		SSL_library_init();

		g_ssl.ctx = SSL_CTX_new(SSLv23_method());

		if (opts->ca_filename) {
			res = SSL_CTX_load_verify_locations(g_ssl.ctx, opts->ca_filename, NULL);
			if (!res) return false;
		}

		long flags = SSL_OP_NO_COMPRESSION;
		SSL_CTX_set_options(g_ssl.ctx, flags);

		long mode = SSL_MODE_ENABLE_PARTIAL_WRITE;
		SSL_CTX_set_mode(g_ssl.ctx, mode);
	}
	#endif

	return true;
}

static void pt_shutdown()
{
	WSACleanup();
}

static SOCKET try_connect(ADDRINFOW *info, int family, ADDRINFOW **used)
{
	for (; info; info = info->ai_next) {
		if (info->ai_family != family) continue;

		SOCKET s = socket(family, SOCK_STREAM, IPPROTO_TCP);
		int res = connect(s, info->ai_addr, (int)info->ai_addrlen);
		if (res == 0) return s;
		closesocket(s);
		*used = info;
	}

	return INVALID_SOCKET;
}

static size_t io_send_imp(pt_io *io, const void *data, size_t size)
{
	if (size == 0) return 0;

	int res;

	#if BQWS_PT_USE_OPENSSL
	if (io->ssl.ssl) {
		if (!io->ssl.connected) {
			res = SSL_connect(io->ssl.ssl);
			if (res <= 0) {
				int err = SSL_get_error(io->ssl.ssl, res);
				if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
					return 0;
				} else {
					return SIZE_MAX;
				}
			}
			io->ssl.connected = true;
		}

		res = SSL_write(io->ssl.ssl, data, (int)size);
		if (res <= 0) {
			int err = SSL_get_error(io->ssl.ssl, res);
			if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
				return 0;
			} else {
				return SIZE_MAX;
			}
		}
		return (size_t)res;
	}
	#endif

	res = send(io->s, data, (int)size, 0);
	if (res < 0) {
		int err = WSAGetLastError();
		if (err == WSAEWOULDBLOCK) return 0;
		return SIZE_MAX;
	}
	return (size_t)res;
}

static bool io_flush_imp(pt_io *io)
{
	size_t size = io->send_size;
	size_t sent = io_send_imp(io, io->send_buf, size);
	if (sent == 0) return true;
	if (sent == SIZE_MAX) return false;

	size_t left = size - sent;
	io->send_size = left;
	if (left > 0) {
		memmove(io->send_buf, io->send_buf + sent, left);
	}
	return true;
}

static size_t io_push_imp(pt_io *io, const char *ptr, const char *end)
{
	size_t size = end - ptr;
	size_t offset = io->send_size;
	size_t to_copy = sizeof(io->send_buf) - offset;
	if (to_copy > size) to_copy = size;
	memcpy(io->send_buf + offset, ptr, to_copy);
	io->send_size += to_copy;
	return to_copy;
}

static bool io_setup_imp(pt_io *io, bool secure, const char *host)
{
	int res;

	io->send_size = 0;

	u_long nb_flag = 1;
	res = ioctlsocket(io->s, FIONBIO, &nb_flag);
	if (res != 0) return false;

	BOOL nd_flag = 1;
	res = setsockopt(io->s, IPPROTO_TCP, TCP_NODELAY, (const char *)&nd_flag, sizeof(nd_flag));
	if (res != 0) return false;

	#if BQWS_PT_USE_OPENSSL
	if (secure) {
		io->ssl.ssl = SSL_new(g_ssl.ctx);
		if (!io->ssl.ssl) return false;

		io->ssl.bio = BIO_new_socket((int)io->s, 0);
		if (!io->ssl.bio) return false;

		SSL_set_bio(io->ssl.ssl, io->ssl.bio, io->ssl.bio);

		if (host) {
			if (!*host) return false;

			X509_VERIFY_PARAM *param = SSL_get0_param(io->ssl.ssl);
			X509_VERIFY_PARAM_set_hostflags(param, /* X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS */ 0x4);
			X509_VERIFY_PARAM_set1_host(param, host, 0);

			SSL_set_verify(io->ssl.ssl, SSL_VERIFY_PEER, NULL);
		}

		io->ssl.connected = false;
	} else {
		io->ssl.ssl = NULL;
	}
	#else
	if (secure) return false;
	#endif

	return true;
}

static size_t pt_io_send(void *user, bqws_socket *ws, const void *data, size_t size)
{
	pt_io *io = (pt_io*)user;

	const char *begin = (const char*)data, *end = begin + size;
	const char *ptr = begin;

	// TODO: Try 2*sizeof(io->send_buf) - io->send_size
	if (size <= sizeof(io->send_buf)) {
		ptr += io_push_imp(io, ptr, end);
		if (ptr != end) {
			if (!io_flush_imp(io)) return SIZE_MAX;
			ptr += io_push_imp(io, ptr, end);
		}
	} else {
		if (io->send_size > 0) {
			ptr += io_push_imp(io, ptr, end);
			if (!io_flush_imp(io)) return SIZE_MAX;
		}

		size_t sent = io_send_imp(io, ptr, end - ptr);
		if (sent == SIZE_MAX) return SIZE_MAX;
		ptr += sent;
	}

	return ptr - begin;
}

static size_t pt_io_recv(void *user, bqws_socket *ws, void *data, size_t max_size, size_t min_size)
{
	if (max_size == 0) return 0;
	pt_io *io = (pt_io*)user;
	int res;

	#if BQWS_PT_USE_OPENSSL
	if (io->ssl.ssl) {
		if (!io->ssl.connected) {
			res = SSL_connect(io->ssl.ssl);
			if (res == 0) {
				int err = SSL_get_error(io->ssl.ssl, res);
				if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
					return 0;
				} else {
					return SIZE_MAX;
				}
			}
			io->ssl.connected = true;
		}

		res = SSL_read(io->ssl.ssl, data, (int)max_size);
		if (res <= 0) {
			int err = SSL_get_error(io->ssl.ssl, res);
			if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
				return 0;
			} else {
				return SIZE_MAX;
			}
		}
		return (size_t)res;
	}
	#endif

	res = recv(io->s, data, (int)max_size, 0);
	if (res < 0) {
		int err = WSAGetLastError();
		if (err == WSAEWOULDBLOCK) return 0;
		return SIZE_MAX;
	}
	return (size_t)res;
}

static bool pt_io_flush(void *user, bqws_socket *ws)
{
	pt_io *io = (pt_io*)user;
	return io_flush_imp(io);
}

static void pt_io_close(void *user, bqws_socket *ws)
{
	pt_io *io = (pt_io*)user;
	closesocket(io->s);
	free(io);
}

static bqws_socket *pt_connect(const bqws_url *url, const bqws_opts *opts, const bqws_client_opts *client_opts)
{
	SOCKET s = INVALID_SOCKET;
	ADDRINFOW *info = NULL;
	pt_io *io = NULL;
	bqws_socket *ws = NULL;

	wchar_t whost[256];
	wchar_t service[32];

	wsprintfW(service, L"%u", (unsigned)url->port);

	bqws_opts opt;
	if (opts) {
		opt = *opts;
	} else {
		memset(&opt, 0, sizeof(opt));
	}

	do {

		int res = MultiByteToWideChar(CP_UTF8, 0, url->host, -1, whost, sizeof(whost) / sizeof(*whost));
		if (res == 0) break;

		ADDRINFOW hints = { 0 };
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		res = GetAddrInfoW(whost, service, &hints, &info);
		if (res != 0) break;

		ADDRINFOW *used_info = NULL;
		SOCKET s = try_connect(info, AF_INET6, &used_info);
		if (s == INVALID_SOCKET) {
			s = try_connect(info, AF_INET, &used_info);
		}
		if (s == INVALID_SOCKET) break;

		io = (pt_io*)malloc(sizeof(pt_io));
		if (!io) break;

		io->s = s;
		if (!io_setup_imp(io, url->secure, url->host)) break;

		// TODO: Retain address?
		FreeAddrInfoW(info);
		info = NULL;

		bqws_opts opt;
		if (opts) {
			opt = *opts;
		} else {
			memset(&opt, 0, sizeof(opt));
		}

		opt.io.user = io;
		opt.io.send_fn = &pt_io_send;
		opt.io.recv_fn = &pt_io_recv;
		opt.io.flush_fn = &pt_io_flush;
		opt.io.close_fn = &pt_io_close;

		ws = bqws_new_client(&opt, client_opts);
		if (!ws) break;

		return ws;

	} while (false);

	// Failure: Free data
	if (info) FreeAddrInfoW(info);
	if (io) free(io);
	if (s != INVALID_SOCKET) closesocket(s);
	return NULL;
}

static bqws_pt_server *pt_listen(const bqws_pt_listen_opts *pt_opts)
{
	SOCKET s = INVALID_SOCKET;
	bqws_pt_server *sv = NULL;
	int res;

	do {
		s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		if (!s) break;

		DWORD ipv6_flag = 0;
		res = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&ipv6_flag, sizeof(ipv6_flag));
		if (res != 0) break;

		u_long nb_flag = 1;
		res = ioctlsocket(s, FIONBIO, &nb_flag);
		if (res != 0) break;

		struct sockaddr_in6 addr = { 0 };
		addr.sin6_family = AF_INET6;
		addr.sin6_addr = in6addr_any;
		addr.sin6_port = htons(pt_opts->port);

		res = bind(s, (struct sockaddr*)&addr, sizeof(addr));
		if (res != 0) break;

		res = listen(s, (int)pt_opts->backlog);
		if (res != 0) break;

		sv = (bqws_pt_server*)malloc(sizeof(bqws_pt_server));
		if (!sv) break;

		sv->s = s;
		sv->secure = pt_opts->secure;
		return sv;

	} while (false);

	if (s != INVALID_SOCKET) closesocket(s);
	if (sv) free(sv);
	return NULL;
}

static void pt_free_server(bqws_pt_server *sv)
{
	closesocket(sv->s);
	free(sv);
}

static bqws_socket *pt_accept(bqws_pt_server *sv, const bqws_opts *opts, const bqws_server_opts *server_opts)
{
	struct sockaddr_in6 addr;
	int addr_len = sizeof(addr);
	SOCKET s = accept(sv->s, (struct sockaddr*)&addr, &addr_len);
	if (s == INVALID_SOCKET) return NULL;

	pt_io *io = NULL;
	bqws_socket *ws = NULL;

	do {

		u_long nb_flag = 1;
		int res = ioctlsocket(s, FIONBIO, &nb_flag);
		if (res != 0) break;

		io = (pt_io*)malloc(sizeof(pt_io));
		if (!io) break;

		io->s = s;
		if (!io_setup_imp(io, sv->secure, NULL)) break;

		bqws_opts opt;
		if (opts) {
			opt = *opts;
		} else {
			memset(&opt, 0, sizeof(opt));
		}

		opt.io.user = io;
		opt.io.send_fn = &pt_io_send;
		opt.io.recv_fn = &pt_io_recv;
		opt.io.flush_fn = &pt_io_flush;
		opt.io.close_fn = &pt_io_close;

		ws = bqws_new_server(&opt, server_opts);
		if (!ws) break;

		return ws;

	} while (false);

	if (io) free(io);
	closesocket(s);
	return NULL;
}

#endif


#endif

// -- Generic

#if defined(_WIN32)
__declspec(thread) static bqws_pt_error t_err;
#else
__thread static bqws_pt_error t_err;
#endif

static void pt_fail_pt(const char *func, bqws_pt_error_code code)
{
	t_err.function = func;
	t_err.type = BQWS_PT_ERRTYPE_PT;
	t_err.data = code;
}

#if defined(__EMSCRIPTEN__) 

#include <emscripten.h>

typedef struct pt_em_partial {
	struct pt_em_partial *next;
	size_t size;
	char data[];
} pt_em_partial;

typedef struct {
	int handle;
	pt_em_partial *partial_first;
	pt_em_partial *partial_last;
	size_t partial_size;
} pt_em_socket;

EMSCRIPTEN_KEEPALIVE void *pt_em_msg_alloc(bqws_socket *ws, size_t size, int type)
{
	bqws_msg *msg = bqws_allocate_msg(ws, (bqws_msg_type)type, size);
	if (!msg) return NULL;
	return msg->data;
}

EMSCRIPTEN_KEEPALIVE void pt_em_msg_recv(bqws_socket *ws, void *ptr)
{
	bqws_msg *msg = (bqws_msg*)((char*)ptr - offsetof(bqws_msg, data));
	bqws_direct_push_msg(ws, msg);
}

EMSCRIPTEN_KEEPALIVE void pt_em_on_open(bqws_socket *ws)
{
	bqws_direct_set_override_state(ws, BQWS_STATE_OPEN);
}

EMSCRIPTEN_KEEPALIVE void pt_em_on_close(bqws_socket *ws)
{
	bqws_direct_set_override_state(ws, BQWS_STATE_CLOSED);
}

EM_JS(int, pt_em_connect_websocket, (bqws_socket *bqws, const char *url, const char **protocols, size_t num_protocols), {
	var url_str = UTF8ToString(url);
	var protocols_str = [];
	for (var i = 0; i < num_protocols; i++) {
		var protocol = HEAPU32[(protocols >> 2) + i];
		protocols_str.push(UTF8ToString(protocol));
	}
	var ws = new WebSocket(url_str, protocols_str);

	ws.binaryType = "arraybuffer";

	if (Module.g_bqws_pt_sockets === undefined) {
		Module.g_bqws_pt_sockets = {
			sockets: [null],
			closed: [true],
			free_list: [],
		};
	}

	var handle = null;
	if (Module.g_bqws_pt_sockets.free_list.length > 0) {
		handle = Module.g_bqws_pt_sockets.free_list.pop();
		Module.g_bqws_pt_sockets.sockets[handle] = ws;
	} else {
		handle = Module.g_bqws_pt_sockets.sockets.length;
		Module.g_bqws_pt_sockets.sockets.push(ws);
	}

	ws.onopen = function(e) {
		if (Module.g_bqws_pt_sockets.sockets[handle] !== ws) return;

		_pt_em_on_open(bqws);
	};
	ws.onclose = function(e) {
		if (Module.g_bqws_pt_sockets.sockets[handle] !== ws) return;

		_pt_em_on_close(bqws);
	};

	ws.onmessage = function(e) {
		if (Module.g_bqws_pt_sockets.sockets[handle] !== ws) return;

		if (typeof e.data === "string") {
			var size = lengthBytesUTF8(e.data);
			var ptr = _pt_em_msg_alloc(bqws, size, 1);
			if (ptr != 0) {
				stringToUTF8(e.data, ptr, size + 1);
				_pt_em_msg_recv(bqws, ptr);
			}
		} else {
			var size = e.data.byteSize;
			var ptr = _pt_em_msg_alloc(bqws, size, 2);
			if (ptr != 0) {
				HEAP8.set(new Uint8Array(e.data), ptr);
				_pt_em_msg_recv(bqws, ptr);
			}
		}
	};

	return handle;
});

EM_JS(int, pt_em_websocket_send_binary, (int handle, const char *data, size_t size), {
	var ws = g_bqws_pt_sockets.sockets[handle];
	if (ws.readyState == 0) {
		return 0;
	} else if (ws.readyState != 1) {
		return 1;
	}

	var view = makeHEAPView("U8", "data", "data+size");
	ws.send(view);
	return 1;
});

EM_JS(int, pt_em_websocket_send_text, (int handle, const char *data, size_t size), {
	var ws = Module.g_bqws_pt_sockets.sockets[handle];
	if (ws.readyState == 0) {
		return 0;
	} else if (ws.readyState != 1) {
		return 1;
	}

	var str = UTF8ToString(data, size);
	ws.send(str);
	return 1;
});

EM_JS(void, pt_em_websocket_close, (int handle, int code), {
	var ws = Module.g_bqws_pt_sockets.sockets[handle];
	if (ws.readyState >= 2) {
		return 0;
	}

	ws.close(code);
});

EM_JS(int, pt_em_free_websocket, (int handle), {
	var ws = Module.g_bqws_pt_sockets.sockets[handle];
	if (ws.readyState < 2) ws.close();

	Module.g_bqws_pt_sockets.sockets[handle] = null;
	Module.g_bqws_pt_sockets.free_list.push(handle);
});

static bool pt_send_message(void *user, bqws_socket *ws, bqws_msg *msg)
{
	pt_em_socket *em = (pt_em_socket*)user;
	void *partial_buf = NULL;

	bqws_msg_type type = msg->type;
	size_t size = msg->size;
	void *data = msg->data;

	if (type & BQWS_MSG_PARTIAL_BIT) {

		pt_em_partial *part = malloc(sizeof(pt_em_partial) + size);
		part->next = NULL;
		part->size = size;
		memcpy(part->data, data, size);
		em->partial_size += size;

		if (em->partial_last) {
			em->partial_last->next = part;
			em->partial_last = part;
		} else {
			em->partial_first = part;
			em->partial_last = part;
		}

		if (type & BQWS_MSG_FINAL_BIT) {
			char *ptr = (char*)malloc(em->partial_size);

			partial_buf = ptr;
			data = ptr;
			size = em->partial_size;
			type = (type & BQWS_MSG_TYPE_MASK);

			pt_em_partial *next = em->partial_first;
			while (next) {
				pt_em_partial *part = next;
				next = part->next;

				memcpy(ptr, part->data, part->size);
				ptr += part->size;

				free(part);
			}

		} else {
			bqws_free_msg(msg);
			return true;
		}
	}

	bool ret = true;

	if (type == BQWS_MSG_BINARY) {
		ret = (bool)pt_em_websocket_send_binary(em->handle, data, size);
	} else if (type == BQWS_MSG_TEXT) {
		ret = (bool)pt_em_websocket_send_text(em->handle, data, size);
	} else if (type == BQWS_MSG_CONTROL_CLOSE) {
		unsigned code = 1000;
		if (msg->size >= 2) {
			code = (unsigned)(uint8_t)msg->data[0] << 8 | (unsigned)(uint8_t)msg->data[1];
		}
		pt_em_websocket_close(em->handle, (int)code);
		ret = true;
	} else {
		// Don't send control messages
	}

	if (partial_buf) {
		free(partial_buf);
		if (ret) {
			em->partial_first = NULL;
			em->partial_last = NULL;
			em->partial_size = 0;
		}
	}

	if (ret) {
		bqws_free_msg(msg);
	}

	return ret;
}

static bool pt_init(const bqws_pt_init_opts *opts)
{
	return true;
}

static void pt_shutdown()
{
}

static size_t pt_io_send(void *user, bqws_socket *ws, const void *data, size_t size)
{
	assert(0 && "Should never get here");
}

static void pt_io_close(void *user, bqws_socket *ws)
{
	pt_em_socket *em = (pt_em_socket*)user;

	pt_em_partial *next = em->partial_first;
	while (next) {
		pt_em_partial *part = next;
		next = part->next;
		free(part);
	}

	pt_em_free_websocket(em->handle);
	free(em);
}

static bqws_socket *pt_connect(const bqws_url *url, const bqws_pt_connect_opts *pt_opts, const bqws_opts *opts, const bqws_client_opts *client_opts)
{
	char url_str[2048];
	int len = snprintf(url_str, sizeof(url_str), "%s://%s:%d%s", url->scheme, url->host, url->port, url->path);
	if (len >= sizeof(url_str)) return NULL;

	bqws_opts opt;
	if (opts) {
		opt = *opts;
	} else {
		memset(&opt, 0, sizeof(opt));
	}

	bqws_client_opts copt;
	if (client_opts) {
		copt = *client_opts;
	} else {
		memset(&copt, 0, sizeof(copt));
	}

	opt.ping_interval = SIZE_MAX;
	opt.ping_response_timeout = SIZE_MAX;
	opt.close_timeout = SIZE_MAX;

	pt_em_socket *em = malloc(sizeof(pt_em_socket));

	opt.send_message_fn = &pt_send_message;
	opt.send_message_user = em;
	opt.io.user = em;
	opt.io.send_fn = &pt_io_send;
	opt.io.close_fn = &pt_io_close;
	opt.skip_handshake = true;

	bqws_socket *ws = bqws_new_client(&opt, &copt);
	if (!ws) {
		free(em);
		return NULL;
	}

	bqws_direct_set_override_state(ws, BQWS_STATE_CONNECTING);

	int handle = pt_em_connect_websocket(ws, url_str, copt.protocols, copt.num_protocols);
	em->handle = handle;

	return ws;
}

static bqws_pt_server *pt_listen(const bqws_pt_listen_opts *opts)
{
	pt_fail_pt("pt_listen", BQWS_PT_ERR_NO_SERVER_SUPPORT);
	return NULL;
}

static bqws_socket *pt_accept(bqws_pt_server *sv, const bqws_opts *opts, const bqws_server_opts *server_opts)
{
	return NULL;
}

static void pt_free_server(bqws_pt_server *sv)
{
}

#elif (defined(_WIN32) || defined (__unix__) || (defined (__APPLE__) && defined (__MACH__)))

#if defined(_WIN32)
// -- OS: Windows

#include <WinSock2.h>
#include <WS2tcpip.h>

#define _WIN32_LEAN_AND_MEAN
#include <Windows.h>

#pragma comment(lib, "ws2_32.lib")


typedef SOCKET os_socket;
#define OS_BAD_SOCKET INVALID_SOCKET

static void pt_fail_wsa(const char *func)
{
	t_err.function = func;
	t_err.type = BQWS_PT_ERRTYPE_WSA;
	t_err.data = (uint32_t)WSAGetLastError();
}

static bool os_init(const bqws_pt_init_opts *opts)
{
	WSADATA data;

	int res = WSAStartup(MAKEWORD(2,2), &data);
	if (res != 0) { pt_fail_wsa("WSAStartup"); return false; }

	return true;
}

static void os_shutdown()
{
	WSACleanup();
}

static bool os_config_listen_socket(os_socket s)
{
	int res;

	// Set the socket to be non-blocking
	u_long nb_flag = 1;
	res = ioctlsocket(s, FIONBIO, &nb_flag);
	if (res != 0) { pt_fail_wsa("ioctlsocket(FIONBIO)"); return false; }

	return true;
}

static bool os_imp_config_data_socket(os_socket s)
{
	int res;

	// Set the socket to be non-blocking
	u_long nb_flag = 1;
	res = ioctlsocket(s, FIONBIO, &nb_flag);
	if (res != 0) { pt_fail_wsa("ioctlsocket(FIONBIO)"); return false; }

	// Disable Nagle's algorithm to make writes immediate
	BOOL nd_flag = 1;
	res = setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&nd_flag, sizeof(nd_flag));
	if (res != 0) { pt_fail_wsa("setsockopt(TCP_NODELAY)"); return false; }

	return true;
}

static os_socket os_imp_try_connect(ADDRINFOW *info, int family, ADDRINFOW **used)
{
	for (; info; info = info->ai_next) {
		if (info->ai_family != family) continue;

		SOCKET s = socket(family, SOCK_STREAM, IPPROTO_TCP);
		int res = connect(s, info->ai_addr, (int)info->ai_addrlen);
		if (res == 0) return s;
		closesocket(s);
		*used = info;
	}

	return INVALID_SOCKET;
}

static os_socket os_socket_connect(const bqws_url *url)
{
	wchar_t whost[256];
	wchar_t service[32];

	wsprintfW(service, L"%u", (unsigned)url->port);

	int res = MultiByteToWideChar(CP_UTF8, 0, url->host, -1, whost, sizeof(whost) / sizeof(*whost));
	if (res == 0) return OS_BAD_SOCKET;

	ADDRINFOW hints = { 0 };
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	ADDRINFOW *info;
	res = GetAddrInfoW(whost, service, &hints, &info);
	if (res != 0) {
		pt_fail_wsa("GetAddrInfoW");
		return INVALID_SOCKET;
	}

	ADDRINFOW *used_info = NULL;
	SOCKET s = os_imp_try_connect(info, AF_INET6, &used_info);
	if (s == INVALID_SOCKET) {
		s = os_imp_try_connect(info, AF_INET, &used_info);
	}

	// TODO: Retain address
	FreeAddrInfoW(info);

	if (!os_imp_config_data_socket(s)) {
		closesocket(s);
		return INVALID_SOCKET;
	}

	return s;
}

static size_t os_socket_recv(os_socket s, void *data, size_t size)
{
	if (size > INT_MAX) size = INT_MAX;

	int res = recv(s, data, (int)size, 0);
	if (res < 0) {
		int err = WSAGetLastError();
		if (err == WSAEWOULDBLOCK) return 0;
		t_err.function = "recv";
		t_err.type = BQWS_PT_ERRTYPE_WSA;
		t_err.data = err;
		return SIZE_MAX;
	}
	return (size_t)res;
}

static size_t os_socket_send(os_socket s, const void *data, size_t size)
{
	if (size > INT_MAX) size = INT_MAX;

	int res = send(s, data, (int)size, 0);
	if (res < 0) {
		int err = WSAGetLastError();
		if (err == WSAEWOULDBLOCK) return 0;
		t_err.function = "send";
		t_err.type = BQWS_PT_ERRTYPE_WSA;
		t_err.data = err;
		return SIZE_MAX;
	}

	return (size_t)res;
}

static void os_socket_close(os_socket s)
{
	shutdown(s, SD_BOTH);
	closesocket(s);
}

#else
	#error "TODO"
#endif

// -- TLS

#if 1

#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct {
	bool connected;
	SSL *ssl;
} pt_tls;

typedef struct {
	SSL_CTX *ctx;
} pt_tls_global;

static pt_tls_global g_tls;

static void pt_fail_ssl(const char *func)
{
	t_err.function = func;
	t_err.type = BQWS_PT_ERRTYPE_OPENSSL;
	t_err.data = ERR_get_error();
}

static bool tls_init(const bqws_pt_init_opts *opts)
{
	int res;

	SSL_library_init();

	g_tls.ctx = SSL_CTX_new(SSLv23_method());
	if (!g_tls.ctx) { pt_fail_ssl("SSL_CTX_new"); return false; }

	if (opts->ca_filename) {
		res = SSL_CTX_load_verify_locations(g_tls.ctx, opts->ca_filename, NULL);
		if (!res) { pt_fail_ssl("SSL_CTX_load_verify_locations"); return false; }
	}

	long flags = SSL_OP_NO_COMPRESSION;
	SSL_CTX_set_options(g_tls.ctx, flags);

	long mode = SSL_MODE_ENABLE_PARTIAL_WRITE;
	SSL_CTX_set_mode(g_tls.ctx, mode);

	return true;
}

static void tls_shutdown()
{
	SSL_CTX_free(g_tls.ctx);
}

static bool tls_init_client(pt_tls *tls, os_socket s, const bqws_pt_connect_opts *pt_opts, const bqws_opts *opts, const bqws_client_opts *client_opts)
{
	tls->ssl = SSL_new(g_tls.ctx);
	if (!tls->ssl) return false;

	BIO *bio = BIO_new_socket((int)s, 0);
	if (!bio) return false;

	// SSL_free() will free the BIO internally
	SSL_set_bio(tls->ssl, bio, bio);

	if (!pt_opts->insecure_no_verify_host) {
		const char *host = client_opts->host;
		if (!host || !*host) return false;

		X509_VERIFY_PARAM *param = SSL_get0_param(tls->ssl);
		X509_VERIFY_PARAM_set_hostflags(param, /* X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS */ 0x4);
		X509_VERIFY_PARAM_set1_host(param, host, 0);

		SSL_set_verify(tls->ssl, SSL_VERIFY_PEER, NULL);
	}
	return true;
}

static bool tls_init_server(pt_tls *tls, const bqws_pt_listen_opts *pt_opts)
{
	// TODO:
	return false;
}

static void tls_free(pt_tls *tls)
{
	if (tls->ssl) SSL_free(tls->ssl);
}

static bool tls_imp_connect(pt_tls *tls)
{
	int res = SSL_connect(tls->ssl);
	if (res <= 0) {
		int err = SSL_get_error(tls->ssl, res);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
			// Did not fail, just did not connect yet
			return true;
		} else {
			pt_fail_ssl("SSL_connect");
			return false;
		}
	}
	tls->connected = true;
	return true;
}

static size_t tls_send(pt_tls *tls, const void *data, size_t size)
{
	if (!tls->connected) {
		if (!tls_imp_connect(tls)) return SIZE_MAX;
		if (!tls->connected) return 0;
	}

	if (size > INT_MAX) size = INT_MAX;
	int res = SSL_write(tls->ssl, data, (int)size);
	if (res <= 0) {
		int err = SSL_get_error(tls->ssl, res);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
			return 0;
		} else {
			pt_fail_ssl("SSL_write");
			return SIZE_MAX;
		}
	}
	return (size_t)res;
}

static size_t tls_recv(pt_tls *tls, void *data, size_t size)
{
	if (!tls->connected) {
		if (!tls_imp_connect(tls)) return SIZE_MAX;
		if (!tls->connected) return 0;
	}

	if (size > INT_MAX) size = INT_MAX;
	int res = SSL_read(tls->ssl, data, (int)size);
	if (res <= 0) {
		int err = SSL_get_error(tls->ssl, res);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
			return 0;
		} else {
			pt_fail_ssl("SSL_read");
			return SIZE_MAX;
		}
	}
	return (size_t)res;
}

#else

typedef struct {
	int unused;
} pt_tls;

static bool tls_init(const bqws_pt_init_opts *opts)
{
	return true;
}

static bool tls_init_socket(pt_tls *tls)
{
	pt_fail_pt("tls_init_socket", BQWS_PT_ERR_NO_TLS);
	return false;
}

static bool tls_init_client(pt_tls *tls, const bqws_pt_connect_opts *pt_opts, const bqws_opts *opts, const bqws_client_opts *client_opts)
{
	pt_fail_pt("tls_init_client", BQWS_PT_ERR_NO_TLS);
	return false;
}

static bool tls_init_server(pt_tls *tls, const bqws_pt_listen_opts *pt_opts)
{
	pt_fail_pt("tls_init_server", BQWS_PT_ERR_NO_TLS);
	return false;
}

static size_t tls_send(pt_tls *tls, const void *data, size_t size)
{
	assert(0 && "Shouldn't get here");
	return SIZE_MAX;
}

static size_t tls_recv(pt_tls *tls, const void *data, size_t size)
{
	assert(0 && "Shouldn't get here");
	return SIZE_MAX;
}

#endif

// -- POSIX socket implementation

typedef struct {
	os_socket s;
	size_t send_size;
	char send_buf[512];

	bool secure;
	pt_tls tls;
} pt_io;

static size_t io_imp_send(pt_io *io, const void *data, size_t size)
{
	if (size == 0) return 0;

	if (io->secure) {
		return tls_send(&io->tls, data, size);
	} else {
		return os_socket_send(io->s, data, size);
	}
}

static bool io_flush_imp(pt_io *io)
{
	size_t size = io->send_size;
	size_t sent = io_imp_send(io, io->send_buf, size);
	if (sent == 0) return true;
	if (sent == SIZE_MAX) return false;

	size_t left = size - sent;
	io->send_size = left;
	if (left > 0) {
		memmove(io->send_buf, io->send_buf + sent, left);
	}
	return true;
}

static size_t io_push_imp(pt_io *io, const char *ptr, const char *end)
{
	size_t size = end - ptr;
	size_t offset = io->send_size;
	size_t to_copy = sizeof(io->send_buf) - offset;
	if (to_copy > size) to_copy = size;
	memcpy(io->send_buf + offset, ptr, to_copy);
	io->send_size += to_copy;
	return to_copy;
}

static size_t io_recv(pt_io *io, const void *data, size_t size)
{
	if (size == 0) return 0;

	if (io->secure) {
		return tls_send(&io->tls, data, size);
	} else {
		return os_socket_send(io->s, data, size);
	}
}

static void io_free(pt_io *io)
{
	if (io->secure) {
		tls_free(&io->tls);
	}
	free(io);
}

static size_t pt_io_send(void *user, bqws_socket *ws, const void *data, size_t size)
{
	if (size == 0) return 0;

	pt_io *io = (pt_io*)user;

	const char *begin = (const char*)data, *end = begin + size;
	const char *ptr = begin;

	// TODO: Try 2*sizeof(io->send_buf) - io->send_size
	if (size <= sizeof(io->send_buf)) {
		ptr += io_push_imp(io, ptr, end);
		if (ptr != end) {
			if (!io_flush_imp(io)) return SIZE_MAX;
			ptr += io_push_imp(io, ptr, end);
		}
	} else {
		if (io->send_size > 0) {
			ptr += io_push_imp(io, ptr, end);
			if (!io_flush_imp(io)) return SIZE_MAX;
		}

		size_t sent = io_imp_send(io, ptr, end - ptr);
		if (sent == SIZE_MAX) return SIZE_MAX;
		ptr += sent;
	}

	return ptr - begin;
}

static size_t pt_io_recv(void *user, bqws_socket *ws, void *data, size_t max_size, size_t min_size)
{
	if (max_size == 0) return 0;

	pt_io *io = (pt_io*)user;
	if (io->secure) {
		return tls_recv(&io->tls, data, max_size);
	} else {
		return os_socket_recv(io->s, data, max_size);
	}
}

static bool pt_io_flush(void *user, bqws_socket *ws)
{
	pt_io *io = (pt_io*)user;
	return io_flush_imp(io);
}

static void pt_io_close(void *user, bqws_socket *ws)
{
	pt_io *io = (pt_io*)user;
	io_free(io);
}

static bool pt_init(const bqws_pt_init_opts *opts)
{
	if (!os_init(opts)) return false;
	if (!tls_init(opts)) {
		os_shutdown();
		return false;
	}

	return true;
}

static void pt_shutdown()
{
	os_shutdown();
}

static bqws_socket *pt_connect(const bqws_url *url, const bqws_pt_connect_opts *pt_opts, const bqws_opts *opts, const bqws_client_opts *client_opts)
{
	os_socket s = OS_BAD_SOCKET;
	pt_io *io = NULL;

	do {
		s = os_socket_connect(url);
		if (s == OS_BAD_SOCKET) break;

		io = malloc(sizeof(pt_io));
		if (!io) break;

		memset(io, 0, sizeof(pt_io));
		io->s = s;

		if (url->secure) {
			io->secure = true;
			if (!tls_init_client(&io->tls, io->s, pt_opts, opts, client_opts)) break;
		}

		bqws_opts opt;
		if (opts) {
			opt = *opts;
		} else {
			memset(&opt, 0, sizeof(opt));
		}

		opt.io.user = io;
		opt.io.send_fn = &pt_io_send;
		opt.io.recv_fn = &pt_io_recv;
		opt.io.flush_fn = &pt_io_flush;
		opt.io.close_fn = &pt_io_close;

		bqws_socket *ws = bqws_new_client(&opt, client_opts);
		if (!ws) break;

		return ws;

	} while (false);

	if (io) io_free(io);
	if (s) os_socket_close(s);
	return NULL;
}

static bqws_pt_server *pt_listen(const bqws_pt_listen_opts *opts)
{
	return NULL;
}

static bqws_socket *pt_accept(bqws_pt_server *sv, const bqws_opts *opts, const bqws_server_opts *server_opts)
{
	return NULL;
}

static void pt_free_server(bqws_pt_server *sv)
{
}

#else
	#error "Unsupported platform"
#endif

// -- API

bool bqws_pt_init(const bqws_pt_init_opts *opts)
{
	bqws_pt_init_opts opt;

	if (opts) {
		opt = *opts;
	} else {
		memset(&opt, 0, sizeof(opt));
	}

	return pt_init(&opt);
}

void bqws_pt_shutdown()
{
	pt_shutdown();
}

void bqws_pt_clear_error()
{
	t_err.function = NULL;
	t_err.type = BQWS_PT_ERRTYPE_NONE;
	t_err.data = 0;
}

bool bqws_pt_get_error(bqws_pt_error *err)
{
	if (t_err.type == BQWS_PT_ERRTYPE_NONE) return false;
	if (err) *err = t_err;
	return true;
}

bqws_socket *bqws_pt_connect(const char *url, const bqws_pt_connect_opts *pt_opts, const bqws_opts *opts, const bqws_client_opts *client_opts)
{
	bqws_url parsed_url;
	if (!bqws_parse_url(&parsed_url, url)) return NULL;
	return bqws_pt_connect_url(&parsed_url, pt_opts, opts, client_opts);
}

bqws_socket *bqws_pt_connect_url(const bqws_url *url, const bqws_pt_connect_opts *pt_opts, const bqws_opts *opts, const bqws_client_opts *client_opts)
{
	bqws_pt_connect_opts popt;
	if (pt_opts) {
		popt = *pt_opts;
	} else {
		memset(&popt, 0, sizeof(popt));
	}

	bqws_opts opt;
	if (opts) {
		opt = *opts;
	} else {
		memset(&opt, 0, sizeof(opt));
	}

	bqws_client_opts copt;
	if (client_opts) {
		copt = *client_opts;
	} else {
		memset(&copt, 0, sizeof(copt));
	}

	if (!copt.host) copt.host = url->host;
	if (!copt.path) copt.path = url->path;

	return pt_connect(url, &popt, &opt, &copt);
}

bqws_pt_server *bqws_pt_listen(const bqws_pt_listen_opts *pt_opts)
{
	bqws_pt_listen_opts opts;
	if (pt_opts) {
		opts = *pt_opts;
	} else {
		memset(&opts, 0, sizeof(opts));
	}

	if (!opts.port) {
		opts.port = opts.secure ? 443 : 80;
	}
	if (!opts.backlog) {
		opts.backlog = 128;
	} else if (opts.backlog > INT32_MAX) {
		opts.backlog = INT32_MAX;
	}

	return pt_listen(&opts);
}

void bqws_pt_free_server(bqws_pt_server *sv)
{
	pt_free_server(sv);
}

bqws_socket *bqws_pt_accept(bqws_pt_server *sv, const bqws_opts *opts, const bqws_server_opts *server_opts)
{
	return pt_accept(sv, opts, server_opts);
}
