#include "bq_websocket_net.h"

#include <string.h>

#ifdef _WIN32

#include <WinSock2.h>

#define _WIN32_LEAN_AND_MEAN
#include <Windows.h>

#pragma comment(lib, "Ws2_32.lib")

typedef struct bqws_net_socket {
	CRITICAL_SECTION mutex;

	SOCKET socket;
	bqws_socket *websocket;

	WSABUF recv_buf;
	WSAOVERLAPPED recv_ov;
	bool recv_async;

	WSABUF send_buf;
	WSAOVERLAPPED send_ov;
	bool send_async;

	WSAOVERLAPPED notify_ov;

} bqws_net_socket;

struct bqws_net_server {
	SOCKET socket;
	bqws_opts opts;
	bqws_server_opts server_opts;
};

HANDLE g_iocp;

static size_t net_io_recv(void *user, bqws_socket *ws, void *data, size_t max_size, size_t min_size)
{
	bqws_net_socket *ns = (bqws_net_socket*)user;
	size_t result = 0;

	size_t offset = 0;

	EnterCriticalSection(&ns->mutex);

	if (ns->recv_async) {
		DWORD num_read, flags;
		BOOL res = WSAGetOverlappedResult(ns->socket, &ns->recv_ov, &num_read, FALSE, &flags);
		if (res == FALSE) {
			LeaveCriticalSection(&ns->mutex);
			return 0;
		}
		ns->recv_async = false;
		result = (size_t)num_read;

		if (result >= min_size) {
			LeaveCriticalSection(&ns->mutex);
			return result;
		} else {
			offset += result;
		}
	}

	ns->recv_buf.buf = (CHAR*)data + offset;
	ns->recv_buf.len = (ULONG)(max_size - offset);

	DWORD num_bytes_instant = 0;
	DWORD flags = 0;
	if (min_size != max_size) flags |= MSG_PUSH_IMMEDIATE;
	else flags |= MSG_WAITALL;
	WSARecv(ns->socket, &ns->recv_buf, 1, &num_bytes_instant, &flags, &ns->recv_ov, NULL);
	if (num_bytes_instant >= min_size) {
		result = (size_t)num_bytes_instant + offset;
	} else {
		ns->recv_async = true;
		result = 0;
	}

	LeaveCriticalSection(&ns->mutex);

	return result;
}

static size_t net_io_send(void *user, bqws_socket *ws, const void *data, size_t size)
{
	bqws_net_socket *ns = (bqws_net_socket*)user;

	size_t result = 0;
	size_t offset = 0;

	EnterCriticalSection(&ns->mutex);

	if (ns->send_async) {
		DWORD num_written, flags;
		BOOL res = WSAGetOverlappedResult(ns->socket, &ns->send_ov, &num_written, FALSE, &flags);
		if (res == FALSE) {
			LeaveCriticalSection(&ns->mutex);
			return 0;
		}
		ns->send_async = false;
		result = (size_t)num_written;

		if (result >= size) {
			LeaveCriticalSection(&ns->mutex);
			return result;
		} else {
			offset += result;
		}
	}

	ns->send_buf.buf = (CHAR*)data + offset;
	ns->send_buf.len = (ULONG)(size - offset);

	DWORD num_bytes_instant = 0;
	DWORD flags = 0;
	WSASend(ns->socket, &ns->send_buf, 1, &num_bytes_instant, flags, &ns->send_ov, NULL);
	if (num_bytes_instant > 0) {
		result = (size_t)num_bytes_instant + offset;
	} else {
		ns->send_async = true;
		result = 0;
	}

	LeaveCriticalSection(&ns->mutex);

	return result;
}

static void net_io_notify(void *user, bqws_socket *ws)
{
	bqws_net_socket *ns = (bqws_net_socket*)user;
	if (ns->websocket == NULL) return;
	PostQueuedCompletionStatus(g_iocp, 1, (ULONG_PTR)ns, &ns->notify_ov);
}

static DWORD WINAPI net_worker_thread(LPVOID arg)
{
	DWORD num_bytes;
	ULONG_PTR user;
	OVERLAPPED *p_overlapped;
	for (;;) {
		BOOL ret = GetQueuedCompletionStatus(g_iocp, &num_bytes, &user, &p_overlapped, INFINITE);
		if (!ret) {
			// TODO?
			break;
		}

		bool do_read = false;
		bool do_write = false;

		bqws_net_socket *ns = (bqws_net_socket*)user;
		EnterCriticalSection(&ns->mutex);

		if (p_overlapped == &ns->recv_ov && ns->recv_async) do_read = true;
		if (p_overlapped == &ns->send_ov && ns->send_async) do_write = true;
		if (p_overlapped == &ns->notify_ov) {
			do_read = true;
			do_write = true;
		}

		LeaveCriticalSection(&ns->mutex);

		if (do_write) {
			bqws_update_io_write(ns->websocket);
		}

		if (do_read) {
			bqws_update_io_read(ns->websocket);
		}
	}

	return 0;
}

static bool net_init(const bqws_net_opts *opts)
{
	WSADATA data;
	if (WSAStartup(MAKEWORD(2,2), &data) != 0) return false;

	g_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);

	CreateThread(NULL, 0, &net_worker_thread, NULL, 0, NULL);

	return true;
}

static void net_start_socket(bqws_socket *ws, bqws_net_socket *ns, SOCKET socket)
{
	ns->websocket = ws;
	ns->socket = socket;

	InitializeCriticalSectionAndSpinCount(&ns->mutex, 1000);

	CreateIoCompletionPort((HANDLE)ns->socket, g_iocp, (ULONG_PTR)ns, 1);
}

static bqws_net_server *net_listen(uint16_t port, const bqws_opts *user_opts, const bqws_server_opts *server_opts)
{
	bqws_net_server *s = malloc(sizeof(bqws_net_server));
	memset(s, 0, sizeof(bqws_net_server));
	if (user_opts) s->opts = *user_opts;
	if (server_opts) s->server_opts = *server_opts;

	s->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.S_un.S_addr = INADDR_ANY;
	bind(s->socket, (struct sockaddr*)&addr, sizeof(addr));
	listen(s->socket, 100);
	u_long val = 1;
	ioctlsocket(s->socket, FIONBIO, &val);

	return s;
}

static bqws_socket *net_accept(bqws_net_server *s)
{
	SOCKET client = accept(s->socket, NULL, NULL);
	if (client == INVALID_SOCKET) return NULL;

	bqws_net_socket *ns = malloc(sizeof(bqws_net_socket));
	memset(ns, 0, sizeof(bqws_net_socket));
	if (!ns) return NULL;

	bqws_opts opts = s->opts;

	opts.io.recv_fn = &net_io_recv;
	opts.io.send_fn = &net_io_send;
	opts.io.notify_fn = &net_io_notify;
	opts.io.user = ns;

	bqws_socket *ws = bqws_new_server(&opts, &s->server_opts);
	if (!ws) return NULL;

	// TODO TODO!
	bqws_server_accept(ws, "");

	net_start_socket(ws, ns, client);

	// Start up the socket
	bqws_update(ws);

	return ws;
}

#else

#include <sys/epoll.h>

int ep_handle; 

static bool net_init(const bqws_net_opts *opts)
{
	ep_handle = epoll_create1(0);

}

#endif

bqws_socket *bqws_net_connect(const char *url, const bqws_opts *user_opts, const bqws_client_opts *client_opts)
{
	bqws_opts opts;
	if (user_opts) {
		opts = *user_opts;
	} else {
		memset(&opts, 0, sizeof(opts));
	}

	return bqws_new_client(&opts, client_opts);
}

bqws_net_server *bqws_net_listen(uint16_t port, const bqws_opts *user_opts, const bqws_server_opts *server_opts)
{
	bqws_opts opts;
	if (user_opts) {
		opts = *user_opts;
	} else {
		memset(&opts, 0, sizeof(opts));
	}

	return net_listen(port, &opts, server_opts);
}

void bqws_net_free_server(bqws_net_server *s)
{
}

bqws_socket *bqws_net_accept(bqws_net_server *s)
{
	return net_accept(s);
}

bool bqws_net_init(const bqws_net_opts *opts)
{
	bqws_net_opts zero_opts;
	if (!opts) {
		memset(&zero_opts, 0, sizeof(zero_opts));
		opts = &zero_opts;
	}


	if (!net_init(opts)) return false;

	return true;
}

void bqws_net_shutdown()
{
}

void bqws_net_update()
{
}
