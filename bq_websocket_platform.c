#include "bq_websocket_platform.h"

#if defined(_WIN32)

#include <WinSock2.h>
#include <WS2tcpip.h>

#define _WIN32_LEAN_AND_MEAN
#include <Windows.h>

#pragma comment(lib, "ws2_32.lib")

typedef struct {
	SOCKET s;
	size_t send_size;
	char send_buf[512];
} pt_io;

struct bqws_pt_server {
	SOCKET s;
};

static void pt_init()
{
	WSADATA data;
	WSAStartup(MAKEWORD(2,2), &data);
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
	int res = send(io->s, data, (int)size, 0);
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

static bool io_setup_imp(pt_io *io)
{
	int res;

	io->send_size = 0;

	u_long nb_flag = 1;
	res = ioctlsocket(io->s, FIONBIO, &nb_flag);
	if (res != 0) return false;

	BOOL nd_flag = 1;
	res = setsockopt(io->s, IPPROTO_TCP, TCP_NODELAY, (const char *)&nd_flag, sizeof(nd_flag));
	if (res != 0) return false;

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
	pt_io *io = (pt_io*)user;
	int res = recv(io->s, data, (int)max_size, 0);
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
		if (!io_setup_imp(io)) break;

		// TODO: Retain address?
		FreeAddrInfoW(info);
		info = NULL;

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
		if (!io_setup_imp(io)) break;

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

// -- API

void bqws_pt_init()
{
	pt_init();
}

void bqws_pt_shutdown()
{
	pt_shutdown();
}

bqws_socket *bqws_pt_connect(const char *url, const bqws_opts *opts, const bqws_client_opts *client_opts)
{
	bqws_url parsed_url;
	if (!bqws_parse_url(&parsed_url, url)) return NULL;
	return bqws_pt_connect_url(&parsed_url, opts, client_opts);
}

bqws_socket *bqws_pt_connect_url(const bqws_url *url, const bqws_opts *opts, const bqws_client_opts *client_opts)
{
	bqws_client_opts copt;
	if (client_opts) {
		copt = *client_opts;
	} else {
		memset(&copt, 0, sizeof(copt));
	}

	if (!copt.host) copt.host = url->host;
	if (!copt.path) copt.path = url->path;

	return pt_connect(url, opts, &copt);
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
