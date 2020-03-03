#include "bq_websocket_platform.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdio.h>

// -- Generic

#ifndef BQWS_PT_USE_OPENSSL
#define BQWS_PT_USE_OPENSSL 0
#endif

#if defined(_WIN32)
__declspec(thread) static bqws_pt_error t_err;
#else
__thread static bqws_pt_error t_err;
#endif

#define BQWS_PT_DELETED_MAGIC  0xbdbdbdbd
#define BQWS_PT_IO_MAGIC       0x77737074
#define BQWS_PT_EM_MAGIC       0x7773656d
#define BQWS_PT_SERVER_MAGIC   0x77737376


#ifndef bqws_assert
#include <assert.h>
#define bqws_assert(x) assert(x)
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
	uint32_t magic;
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
	ws.onerror = function(e) {
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
			var size = e.data.byteLength;
			var ptr = _pt_em_msg_alloc(bqws, size, 2);
			if (ptr != 0) {
				HEAPU8.set(new Uint8Array(e.data), ptr);
				_pt_em_msg_recv(bqws, ptr);
			}
		}
	};

	return handle;
});

EM_JS(int, pt_em_websocket_send_binary, (int handle, const char *data, size_t size), {
	var ws = Module.g_bqws_pt_sockets.sockets[handle];
	if (ws.readyState == 0) {
		return 0;
	} else if (ws.readyState != 1) {
		return 1;
	}

	ws.send(HEAPU8.subarray(data, data + size));
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
	bqws_assert(0 && "Should never get here");
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
	em->magic = BQWS_PT_DELETED_MAGIC;
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
	memset(em, 0, sizeof(pt_em_socket));
	em->magic = BQWS_PT_EM_MAGIC;

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
	pt_fail_pt("pt_listen()", BQWS_PT_ERR_NO_SERVER_SUPPORT);
	return NULL;
}

static bqws_socket *pt_accept(bqws_pt_server *sv, const bqws_opts *opts, const bqws_server_opts *server_opts)
{
	return NULL;
}

static void pt_free_server(bqws_pt_server *sv)
{
}

static bqws_pt_address pt_get_address(const bqws_socket *ws)
{
	pt_em_socket *em = (pt_em_socket*)bqws_get_io_user(ws);
	bqws_assert(em && em->magic == BQWS_PT_EM_MAGIC);
	bqws_pt_address addr = { BQWS_PT_ADDRESS_WEBSOCKET };
	memcpy(addr.address, &em->handle, sizeof(int));
	return addr;
}

#elif (defined(_WIN32) || defined (__unix__) || (defined (__APPLE__) && defined (__MACH__)))

// -- Shared for Windows and POSIX

static const uint8_t ipv4_mapped_ipv6_prefix[] = {
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,
};

static void addr_parse_ipv4(bqws_pt_address *dst, const void *addr, uint16_t port_native)
{
	dst->port = port_native;
	dst->type = BQWS_PT_ADDRESS_IPV4;
	memcpy(dst->address, addr, 4);
}

static void addr_parse_ipv6(bqws_pt_address *dst, const void *addr, uint16_t port_native)
{
	dst->port = port_native;
	if (!memcmp(addr, ipv4_mapped_ipv6_prefix, sizeof(ipv4_mapped_ipv6_prefix))) {
		dst->type = BQWS_PT_ADDRESS_IPV4;
		memcpy(dst->address, (const char*)addr + 12, 4);
	} else {
		dst->type = BQWS_PT_ADDRESS_IPV6;
		memcpy(dst->address, addr, 16);
	}
}

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
	if (res != 0) { pt_fail_wsa("WSAStartup()"); return false; }

	return true;
}

static void os_shutdown()
{
	WSACleanup();
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
		if (s == INVALID_SOCKET) { pt_fail_wsa("socket()"); return s; }
		int res = connect(s, info->ai_addr, (int)info->ai_addrlen);
		if (res == 0) {
			*used = info;
			return s;
		}
		pt_fail_wsa("connect()");
		closesocket(s);
	}

	return INVALID_SOCKET;
}

static void os_imp_parse_address(bqws_pt_address *dst, struct sockaddr *addr)
{
	if (addr->sa_family == AF_INET) {
		struct sockaddr_in *sa = (struct sockaddr_in*)addr;
		addr_parse_ipv4(dst, &sa->sin_addr, ntohs(sa->sin_port));
	} else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *sa = (struct sockaddr_in6*)addr;
		addr_parse_ipv6(dst, &sa->sin6_addr, ntohs(sa->sin6_port));
	}
}

static os_socket os_socket_connect(const bqws_url *url, bqws_pt_address *addr)
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
		pt_fail_wsa("GetAddrInfoW()");
		return INVALID_SOCKET;
	}

	ADDRINFOW *used_info = NULL;
	SOCKET s = os_imp_try_connect(info, AF_INET6, &used_info);
	if (s == INVALID_SOCKET) {
		s = os_imp_try_connect(info, AF_INET, &used_info);
	}

	if (s != INVALID_SOCKET) {
		os_imp_parse_address(addr, used_info->ai_addr);
	}

	FreeAddrInfoW(info);

	if (!os_imp_config_data_socket(s)) {
		closesocket(s);
		return INVALID_SOCKET;
	}

	return s;
}

static os_socket os_socket_listen(const bqws_pt_listen_opts *pt_opts)
{
	os_socket s = OS_BAD_SOCKET;
	int res;

	do {
		s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		if (s == INVALID_SOCKET) { pt_fail_wsa("socket()"); break; }

		// Make sure the socket supports both IPv4 and IPv6
		DWORD ipv6_flag = 0;
		res = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&ipv6_flag, sizeof(ipv6_flag));
		if (res != 0) { pt_fail_wsa("setsockopt(IPPROTO_IPV6)"); break; }

		// Set the socket to be non-blocking
		u_long nb_flag = 1;
		res = ioctlsocket(s, FIONBIO, &nb_flag);
		if (res != 0) { pt_fail_wsa("ioctlsocket(FIONBIO)"); break; }

		struct sockaddr_in6 addr = { 0 };
		addr.sin6_family = AF_INET6;
		addr.sin6_addr = in6addr_any;
		addr.sin6_port = htons(pt_opts->port);

		res = bind(s, (struct sockaddr*)&addr, sizeof(addr));
		if (res != 0) { pt_fail_wsa("bind()"); break; }

		res = listen(s, (int)pt_opts->backlog);
		if (res != 0) { pt_fail_wsa("listen()"); break; }

		return s;

	} while (false);

	if (s != INVALID_SOCKET) closesocket(s);
	return INVALID_SOCKET;
}

static os_socket os_socket_accept(os_socket listen_s, bqws_pt_address *addr)
{
	struct sockaddr_in6 addr_in;
	int addr_len = sizeof(addr_in);
	SOCKET s = accept(listen_s, (struct sockaddr*)&addr_in, &addr_len);
	if (s == INVALID_SOCKET) return INVALID_SOCKET;

	os_imp_parse_address(addr, (struct sockaddr*)&addr_in);

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
		t_err.function = "recv()";
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
		t_err.function = "send()";
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

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/tcp.h>

// TODO: Guard this with macros?
#if 1
	#include <netdb.h>
	#define BQWS_HAS_GAI_STRERROR
#endif

typedef int os_socket;
#define OS_BAD_SOCKET -1

static void pt_fail_posix(const char *func)
{
	t_err.function = func;
	t_err.type = BQWS_PT_ERRTYPE_POSIX;
	t_err.data = errno;
}

static bool os_init(const bqws_pt_init_opts *opts)
{
	return true;
}

static void os_shutdown()
{
}

static bool os_imp_config_data_socket(os_socket s)
{
	int res;

	// Set the socket to be non-blocking
	int nb_flag = 1;
	res = ioctl(s, FIONBIO, &nb_flag);
	if (res != 0) { pt_fail_posix("ioctl(FIONBIO)"); return false; }

	// Disable Nagle's algorithm to make writes immediate
	int nd_flag = 1;
	res = setsockopt(s, SOL_TCP, TCP_NODELAY, &nd_flag, sizeof(nd_flag));
	if (res != 0) { pt_fail_posix("setsockopt(TCP_NODELAY)"); return false; }

	return true;
}

static os_socket os_imp_try_connect(struct addrinfo *info, int family, struct addrinfo **used)
{
	for (; info; info = info->ai_next) {
		if (info->ai_family != family) continue;

		int s = socket(family, SOCK_STREAM, IPPROTO_TCP);
		if (s == -1) { pt_fail_posix("socket()"); return s; }
		int res = connect(s, info->ai_addr, (int)info->ai_addrlen);
		if (res == 0) {
			*used = info;
			return s;
		}
		pt_fail_posix("connect()");
		close(s);
	}

	return -1;
}

static void os_imp_parse_address(bqws_pt_address *dst, struct sockaddr *addr)
{
	if (addr->sa_family == AF_INET) {
		struct sockaddr_in *sa = (struct sockaddr_in*)addr;
		addr_parse_ipv4(dst, &sa->sin_addr, ntohs(sa->sin_port));
	} else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *sa = (struct sockaddr_in6*)addr;
		addr_parse_ipv6(dst, &sa->sin6_addr, ntohs(sa->sin6_port));
	}
}

static os_socket os_socket_connect(const bqws_url *url, bqws_pt_address *addr)
{
	char service[64];
	snprintf(service, sizeof(service), "%d", (int)url->port);

	struct addrinfo hints = { 0 };
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	struct addrinfo *info;
	int res = getaddrinfo(url->host, service, &hints, &info);
	if (res != 0) {
		t_err.function = "getaddrinfo()";
		t_err.type = BQWS_PT_ERRTYPE_GETADDRINFO;
		t_err.data = res;
		return -1;
	}

	struct addrinfo *used_info = NULL;
	int s = os_imp_try_connect(info, AF_INET6, &used_info);
	if (s == -1) {
		s = os_imp_try_connect(info, AF_INET, &used_info);
	}

	if (s != -1) {
		os_imp_parse_address(addr, used_info->ai_addr);
	}

	freeaddrinfo(info);

	if (!os_imp_config_data_socket(s)) {
		close(s);
		return -1;
	}

	return s;
}

static os_socket os_socket_listen(const bqws_pt_listen_opts *pt_opts)
{
	os_socket s = -1;
	int res;

	do {
		s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		if (s == -1) { pt_fail_posix("socket()"); break; }

		// Make sure the socket supports both IPv4 and IPv6
		int ipv6_flag = 0;
		res = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_flag, sizeof(ipv6_flag));
		if (res != 0) { pt_fail_posix("setsockopt(IPPROTO_IPV6)"); break; }

		// Set the socket to be non-blocking
		int nb_flag = 1;
		res = ioctl(s, FIONBIO, &nb_flag);
		if (res != 0) { pt_fail_posix("ioctl(FIONBIO)"); break; }

		struct sockaddr_in6 addr = { 0 };
		addr.sin6_family = AF_INET6;
		addr.sin6_addr = in6addr_any;
		addr.sin6_port = htons(pt_opts->port);

		res = bind(s, (struct sockaddr*)&addr, sizeof(addr));
		if (res != 0) { pt_fail_posix("bind()"); break; }

		res = listen(s, (int)pt_opts->backlog);
		if (res != 0) { pt_fail_posix("listen()"); break; }

		return s;

	} while (false);

	if (s != -1) close(s);
	return -1;
}

static os_socket os_socket_accept(os_socket listen_s, bqws_pt_address *addr)
{
	struct sockaddr_in6 addr_in;
	socklen_t addr_len = sizeof(addr_in);
	int s = accept(listen_s, (struct sockaddr*)&addr_in, &addr_len);
	if (s == -1) return -1;

	os_imp_parse_address(addr, (struct sockaddr*)&addr_in);

	if (!os_imp_config_data_socket(s)) {
		close(s);
		return -1;
	}

	return s;
}

static size_t os_socket_recv(os_socket s, void *data, size_t size)
{
	int res = read(s, data, size);
	if (res < 0) {
		int err = errno;
		if (err == EAGAIN || err == EWOULDBLOCK) return 0;
		t_err.function = "read()";
		t_err.type = BQWS_PT_ERRTYPE_POSIX;
		t_err.data = err;
		return SIZE_MAX;
	}
	return (size_t)res;
}

static size_t os_socket_send(os_socket s, const void *data, size_t size)
{
	int res = write(s, data, size);
	if (res < 0) {
		int err = errno;
		if (err == EAGAIN || err == EWOULDBLOCK) return 0;
		t_err.function = "write()";
		t_err.type = BQWS_PT_ERRTYPE_POSIX;
		t_err.data = err;
		return SIZE_MAX;
	}
	return (size_t)res;
}

static void os_socket_close(os_socket s)
{
	shutdown(s, SHUT_RDWR);
	close(s);
}

#endif

// -- TLS

#if BQWS_PT_USE_OPENSSL

#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct {
	bool connected;
	SSL *ssl;
} pt_tls;

typedef struct {
	SSL_CTX *ctx;
} pt_tls_server;

typedef struct {
	SSL_CTX *client_ctx;
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

	g_tls.client_ctx = SSL_CTX_new(SSLv23_client_method());
	if (!g_tls.client_ctx) { pt_fail_ssl("SSL_CTX_new()"); return false; }

	if (opts->ca_filename) {
		res = SSL_CTX_load_verify_locations(g_tls.client_ctx, opts->ca_filename, NULL);
		if (!res) { pt_fail_ssl("SSL_CTX_load_verify_locations()"); return false; }
	}

	long flags = SSL_OP_NO_COMPRESSION;
	SSL_CTX_set_options(g_tls.client_ctx, flags);

	long mode = SSL_MODE_ENABLE_PARTIAL_WRITE;
	SSL_CTX_set_mode(g_tls.client_ctx, mode);

	return true;
}

static void tls_shutdown()
{
	SSL_CTX_free(g_tls.client_ctx);
}

static bool tls_init_client(pt_tls *tls, os_socket s, const bqws_pt_connect_opts *pt_opts, const bqws_opts *opts, const bqws_client_opts *client_opts)
{
	tls->ssl = SSL_new(g_tls.client_ctx);
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

static bool tls_init_server(pt_tls_server *tls, const bqws_pt_listen_opts *pt_opts)
{
	tls->ctx = SSL_CTX_new(SSLv23_server_method());
	if (!tls->ctx) { pt_fail_ssl("SSL_CTX_new()"); return false; }

	int res;

	if (pt_opts->certificate_file) {
		res = SSL_CTX_use_certificate_file(tls->ctx, pt_opts->certificate_file, SSL_FILETYPE_PEM);
		if (!res) { pt_fail_ssl("SSL_CTX_use_certificate_file()"); return false; }
	}

	if (pt_opts->private_key_file) {
		res = SSL_CTX_use_PrivateKey_file(tls->ctx, pt_opts->private_key_file, SSL_FILETYPE_PEM);
		if (!res) { pt_fail_ssl("SSL_CTX_use_PrivateKey_file()"); return false; }
	}

	long flags = SSL_OP_NO_COMPRESSION;
	SSL_CTX_set_options(tls->ctx, flags);

	long mode = SSL_MODE_ENABLE_PARTIAL_WRITE;
	SSL_CTX_set_mode(tls->ctx, mode);

	return true;
}

static void tls_free_server(pt_tls_server *tls)
{
	if (tls->ctx) {
		SSL_CTX_free(tls->ctx);
	}
}

static bool tls_init_accept(pt_tls *tls, pt_tls_server *tls_server, os_socket s)
{
	tls->ssl = SSL_new(tls_server->ctx);
	if (!tls->ssl) return false;

	BIO *bio = BIO_new_socket((int)s, 0);
	if (!bio) return false;

	// SSL_free() will free the BIO internally
	SSL_set_bio(tls->ssl, bio, bio);

	return true;
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
			pt_fail_ssl("SSL_connect()");
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
			pt_fail_ssl("SSL_write()");
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
			pt_fail_ssl("SSL_read()");
			return SIZE_MAX;
		}
	}
	return (size_t)res;
}

#else

typedef struct {
	int unused;
} pt_tls;

typedef struct {
	int unused;
} pt_tls_server;

static bool tls_init(const bqws_pt_init_opts *opts)
{
	return true;
}

static void tls_shutdown()
{
}

static bool tls_init_client(pt_tls *tls, os_socket s, const bqws_pt_connect_opts *pt_opts, const bqws_opts *opts, const bqws_client_opts *client_opts)
{
	pt_fail_pt("tls_init_client()", BQWS_PT_ERR_NO_TLS);
	return false;
}

static bool tls_init_server(pt_tls_server *tls, const bqws_pt_listen_opts *pt_opts)
{
	pt_fail_pt("tls_init_client()", BQWS_PT_ERR_NO_TLS);
	return false;
}

static void tls_free_server(pt_tls_server *tls)
{
}

static bool tls_init_accept(pt_tls *tls, pt_tls_server *tls_server, os_socket s)
{
	bwqs_assert(0 && "Should never get here");
}

static void tls_free(pt_tls *tls)
{
}

static size_t tls_send(pt_tls *tls, const void *data, size_t size)
{
	bwqs_assert(0 && "Should never get here");
	return SIZE_MAX;
}

static size_t tls_recv(pt_tls *tls, void *data, size_t size)
{
	bwqs_assert(0 && "Should never get here");
	return SIZE_MAX;
}

#endif

// -- POSIX socket implementation

typedef struct {
	uint32_t magic;

	os_socket s;
	size_t send_size;
	char send_buf[512];

	bool secure;
	pt_tls tls;

	bqws_pt_address address;
} pt_io;

struct bqws_pt_server {
	uint32_t magic;

	os_socket s;
	bool secure;
	pt_tls_server tls;
};

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
	io->magic = BQWS_PT_DELETED_MAGIC;
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
		bqws_pt_address addr = { 0 };
		s = os_socket_connect(url, &addr);
		if (s == OS_BAD_SOCKET) break;

		io = malloc(sizeof(pt_io));
		if (!io) break;

		memset(io, 0, sizeof(pt_io));
		io->magic = BQWS_PT_IO_MAGIC;
		io->s = s;
		io->address = addr;

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
	if (s != OS_BAD_SOCKET) os_socket_close(s);
	return NULL;
}

static bqws_pt_server *pt_listen(const bqws_pt_listen_opts *pt_opts)
{
	bqws_pt_server *sv = (bqws_pt_server*)malloc(sizeof(bqws_pt_server));
	if (!sv) { pt_fail_pt("pt_listen()", BQWS_PT_ERR_OUT_OF_MEMORY); return NULL; }
	memset(sv, 0, sizeof(bqws_pt_server));
	sv->magic = BQWS_PT_SERVER_MAGIC;

	if (pt_opts->secure) {
		sv->secure = true;
		if (!tls_init_server(&sv->tls, pt_opts)) {
			free(sv);
			return NULL;
		}
	}

	sv->s = os_socket_listen(pt_opts);
	if (sv->s == OS_BAD_SOCKET) {
		free(sv);
		return NULL;
	}

	return sv;
}

static bqws_socket *pt_accept(bqws_pt_server *sv, const bqws_opts *opts, const bqws_server_opts *server_opts)
{
	bqws_assert(sv && sv->magic == BQWS_PT_SERVER_MAGIC);

	bqws_pt_address addr = { 0 };
	os_socket s = os_socket_accept(sv->s, &addr);
	if (s == OS_BAD_SOCKET) return NULL;

	pt_io *io = NULL;

	do {
		io = malloc(sizeof(pt_io));
		if (!io) break;

		memset(io, 0, sizeof(pt_io));
		io->magic = BQWS_PT_IO_MAGIC;
		io->s = s;
		io->address = addr;

		if (sv->secure) {
			io->secure = true;
			if (!tls_init_accept(&io->tls, &sv->tls, s)) return false;
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

		bqws_socket *ws = bqws_new_server(&opt, server_opts);
		if (!ws) break;

		return ws;

	} while (false);

	if (io) free(io);
	os_socket_close(s);
	return NULL;
}

static void pt_free_server(bqws_pt_server *sv)
{
	bqws_assert(sv && sv->magic == BQWS_PT_SERVER_MAGIC);

	if (sv->secure) {
		tls_free_server(&sv->tls);
	}
	os_socket_close(sv->s);
	sv->magic = BQWS_PT_DELETED_MAGIC;
	free(sv);
}

static bqws_pt_address pt_get_address(const bqws_socket *ws)
{
	pt_io *io = (pt_io*)bqws_get_io_user(ws);
	bqws_assert(io && io->magic == BQWS_PT_IO_MAGIC);

	return io->address;
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
	bqws_pt_clear_error();

	bqws_url parsed_url;
	if (!bqws_parse_url(&parsed_url, url)) {
		pt_fail_pt("bqws_parse_url()", BQWS_PT_ERR_BAD_URL);
		return NULL;
	}
	return bqws_pt_connect_url(&parsed_url, pt_opts, opts, client_opts);
}

bqws_socket *bqws_pt_connect_url(const bqws_url *url, const bqws_pt_connect_opts *pt_opts, const bqws_opts *opts, const bqws_client_opts *client_opts)
{
	bqws_pt_clear_error();

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
	bqws_pt_clear_error();

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
	if (!sv) return;
	pt_free_server(sv);
}

bqws_socket *bqws_pt_accept(bqws_pt_server *sv, const bqws_opts *opts, const bqws_server_opts *server_opts)
{
	bqws_pt_clear_error();

	return pt_accept(sv, opts, server_opts);
}

bqws_pt_address bqws_pt_get_address(const bqws_socket *ws)
{
	bqws_assert(ws);
	return pt_get_address(ws);
}

void bqws_pt_format_address(char *dst, size_t size, const bqws_pt_address *addr)
{
	if (size == 0) return;

	switch (addr->type) {

	case BQWS_PT_ADDRESS_UNKNOWN:
		snprintf(dst, size, "(unknown)");
		break;

	case BQWS_PT_ADDRESS_WEBSOCKET:
		snprintf(dst, size, "websocket[%d]", *(int*)addr->address);
		break;

	case BQWS_PT_ADDRESS_IPV4:
		snprintf(dst, size, "%u.%u.%u.%u:%u",
			(unsigned)addr->address[0], (unsigned)addr->address[1],
			(unsigned)addr->address[2], (unsigned)addr->address[3],
			(unsigned)addr->port);
		break;

	case BQWS_PT_ADDRESS_IPV6:
		{
			const uint8_t *a = addr->address;

			// Find the leftmost longest run of zeros that's longer than one
			size_t longest_begin = SIZE_MAX;
			size_t longest_zeros = 1;
			{
				size_t zeros = 0;
				size_t zero_begin = 0;
				for (size_t i = 0; i < 16; i += 2) {
					if (a[i] == 0 && a[i + 1] == 0) {
						if (zeros == 0) {
							zero_begin = i;
						}
						zeros++;
						if (zeros > longest_zeros) {
							longest_begin = zero_begin;
							longest_zeros = zeros;
						}
					} else {
						zeros = 0;
					}
				}
			}

			bool need_colon = false;
			char *ptr = dst, *end = dst + size;
			ptr += snprintf(ptr, end - ptr, "[");
			for (size_t i = 0; i < 16; i += 2) {
				if (i == longest_begin) {
					ptr += snprintf(ptr, end - ptr, "::");
					need_colon = false;
					i += (longest_zeros - 1) * 2;
					continue;
				}

				unsigned v = (unsigned)a[i] << 8 | (unsigned)a[i + 1];
				ptr += snprintf(ptr, end - ptr, need_colon ? ":%x" : "%x", v);

				need_colon = true;
			}
			ptr += snprintf(ptr, end - ptr, "]:%u", (unsigned)addr->port);
		}
		break;

	default:
		snprintf(dst, size, "(bad type)");
		break;
	}
}

void bqws_pt_get_error_desc(char *dst, size_t size, const bqws_pt_error *err)
{
	if (size == 0) return;

	*dst = '\0';

	switch (err->type) {

	case BQWS_PT_ERRTYPE_NONE:
		// Nop, empty description
		break;

	case BQWS_PT_ERRTYPE_PT:
		{
			const char *str = bqws_pt_error_code_str((bqws_pt_error_code)err->data);
			size_t len = strlen(str);
			if (len > size) len = size;
			memcpy(dst, str, len);
			dst[len] = '\0';
		}
		break;

	case BQWS_PT_ERRTYPE_WSA:
		#if defined(_WIN32)
		{
			wchar_t *buf;
			FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, 
				NULL, (DWORD)err->data,
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				(LPWSTR)&buf, 0, NULL);

			int int_size = size < INT_MAX ? (int)size : INT_MAX;
			int res = WideCharToMultiByte(CP_UTF8, 0, buf, -1, dst, int_size, NULL, NULL);
			if (res == 0) {
				*dst = '\0';
			} else if (res >= int_size) {
				dst[int_size] = '\0';
			}
		}
		#endif
		break;

	case BQWS_PT_ERRTYPE_POSIX:
		#if defined(_WIN32)
			strerror_s(dst, size, (int)err->data);
		#else
			strerror_r((int)err->data, dst, size);
		#endif
		break;

	case BQWS_PT_ERRTYPE_GETADDRINFO:
		#if defined(BQWS_HAS_GAI_STRERROR)
		{
			const char *str = gai_strerror((int)err->data);
			size_t len = strlen(str);
			if (len > size) len = size;
			memcpy(dst, str, len);
			dst[len] = '\0';
		}
		#endif
		break;

	case BQWS_PT_ERRTYPE_OPENSSL:
		#if BQWS_PT_USE_OPENSSL
			ERR_error_string_n((unsigned long)err->data, dst, size);
		#endif
		break;

	}
}

const char *bqws_pt_error_type_str(bqws_pt_error_type type)
{
	switch (type) {
	case BQWS_PT_ERRTYPE_NONE: return "NONE";
	case BQWS_PT_ERRTYPE_PT: return "PT";
	case BQWS_PT_ERRTYPE_WSA: return "WSA";
	case BQWS_PT_ERRTYPE_POSIX: return "POSIX";
	case BQWS_PT_ERRTYPE_GETADDRINFO: return "GETADDRINFO";
	case BQWS_PT_ERRTYPE_OPENSSL: return "OPENSSL";
	default: return "(unknown)";
	}
}

const char *bqws_pt_error_code_str(bqws_pt_error_code err)
{
	switch (err) {
	case BQWS_PT_OK: return "OK";
	case BQWS_PT_ERR_NO_TLS: return "NO_TLS: bq_websocket_platform.c was built without TLS support";
	case BQWS_PT_ERR_NO_SERVER_SUPPORT: return "NO_SERVER_SUPPORT: The platform doesn't support server sockets";
	case BQWS_PT_ERR_OUT_OF_MEMORY: return "OUT_OF_MEMORY: Failed to allocate memory";
	case BQWS_PT_ERR_BAD_URL: return "BAD_URL: Could not parse URL";
	default: return "(unknown)";
	}
}
