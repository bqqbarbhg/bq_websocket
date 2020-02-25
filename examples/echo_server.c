#if 0
#include "../bq_websocket.h"
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

// -- Platform

#ifdef _WIN32

#include <WinSock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

#define _WIN32_LEAN_AND_MEAN
#include <Windows.h>

typedef SOCKET os_socket;

void check(bool cond)
{
	if (!cond) {
		exit(1);
	}
}

void os_setup_sockets()
{
	WSADATA data;
	check(WSAStartup(MAKEWORD(2,2), &data) == 0);
}

void os_teardown_sockets()
{
	WSACleanup();
}

os_socket os_open_listen(uint16_t port, int backlog)
{
	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	check(s != INVALID_SOCKET);
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.S_un.S_addr = INADDR_ANY;
	check(bind(s, (struct sockaddr*)&addr, sizeof(addr)) == 0);
	check(listen(s, backlog) == 0);
	u_long val = 1;
	check(ioctlsocket(s, FIONBIO, &val) == 0);
	return s;
}

bool os_accept(os_socket s, os_socket *client)
{
	SOCKET c = accept(s, NULL, NULL);
	if (c != INVALID_SOCKET) {
		u_long val = 1;
		check(ioctlsocket(c, FIONBIO, &val) == 0);
		*client = c;
		return true;
	} else {
		return false;
	}
}

void os_close(os_socket s)
{
	check(shutdown(s, SD_SEND) == 0);
	check(closesocket(s) == 0);
}

size_t os_send(void *user, bqws_socket *ws, const void *data, size_t size)
{
	os_socket s = *(os_socket*)user;
	int res = send(s, data, (int)size, 0);
	if (res < 0) {
		return WSAGetLastError() == WSAEWOULDBLOCK ? 0 : SIZE_MAX;
	}
	return (size_t)res;
}

size_t os_recv(void *user, bqws_socket *ws, void *data, size_t size)
{
	os_socket s = *(os_socket*)user;
	int res = recv(s, data, (int)size, 0);
	if (res < 0) {
		return WSAGetLastError() == WSAEWOULDBLOCK ? 0 : SIZE_MAX;
	}
	return (size_t)res;
}

void os_sleep(size_t ms)
{
	Sleep((DWORD)ms);
}

#endif

// -- Server

#define MAX_CLIENTS 32

typedef struct {
	bool used;
	os_socket socket;
	bqws_socket *websocket;
	size_t index;
} client;

typedef struct {
	os_socket socket;
	client clients[MAX_CLIENTS];
} server;

void setup_client(client *c);
void update_client(client *c);
void close_client(client *c);

void setup_server(server *s, uint16_t port)
{
	s->socket = os_open_listen(port, MAX_CLIENTS);
	for (size_t i = 0; i < MAX_CLIENTS; i++) {
		s->clients[i].index = i;
	}
}

void update_server(server *s)
{
	bool tried_accept = false;
	for (size_t i = 0; i < MAX_CLIENTS; i++) {
		client *c = &s->clients[i];

		// Try to accept a new client
		if (!c->used) {
			if (!tried_accept) {
				tried_accept = true;
				if (os_accept(s->socket, &c->socket)) {
					setup_client(c);
				}
			}
		} else {
			update_client(c);
		}
	}
}

void close_server(server *s)
{
	for (size_t i = 0; i < MAX_CLIENTS; i++) {
		if (!s->clients[i].used) continue;
		bqws_free_socket(s->clients[i].websocket);
		os_close(s->clients[i].socket);
	}

	os_close(s->socket);
}

// -- Actual API usage

void log_fn(void *user, bqws_socket *ws, const char *line)
{
	client *c = *(client**)bqws_user_data(ws);
	printf("%zu: %s\n", c->index, line);
}

void setup_client(client *c)
{
	c->used = true;

	// Forward IO to OS socket functions
	bqws_opts opts = { 0 };
	opts.io.recv_fn = &os_recv;
	opts.io.send_fn = &os_send;
	opts.io.user = (void*)&c->socket;
	opts.log_fn = &log_fn;
	opts.user_data = &c;
	opts.user_size = sizeof(c);

	// Set the server options to auto accept
	// with WebSocket user protocol "echo"
	bqws_client_opts filter = { 0 };
	filter.protocols[0] = "echo";
	filter.num_protocols = 1;
	bqws_server_opts server_opts = { 0 };
	server_opts.verify_filter = &filter;

	c->websocket = bqws_new_server(&opts, &server_opts);
}

void close_client(client *c)
{
	bqws_free_socket(c->websocket);
	os_close(c->socket);

	c->used = false;
}

void update_client(client *c)
{
	bqws_socket *ws = c->websocket;

	bqws_update(ws);

	bqws_msg *msg;
	while ((msg = bqws_recv(ws)) != NULL) {
		if (msg->type == BQWS_MSG_TEXT) {
			// Text message: Change capitalization and
			// send it back using the same buffer
			for (size_t i = 0; i < msg->size; i++) {
				char c = msg->data[i];
				msg->data[i] = rand() % 2 == 0 ? toupper(c) : tolower(c);
			}
			bqws_send_msg(ws, msg);
		} else {
			// Binary message: Respond with an error
			// text message and free the message buffer
			bqws_send_str(ws, "Text messages only!");
			bqws_free_msg(msg);
		}
	}

	if (bqws_is_closed(ws)) {
		close_client(c);
		return;
	}
}

int main(int argc, char **argv)
{
	os_setup_sockets();

	server s = { 0 };
	setup_server(&s, 4004);

	for (;;) {
		update_server(&s);
		os_sleep(10);
	}

	close_server(&s);

	os_teardown_sockets();

	return 0;
}
#endif
