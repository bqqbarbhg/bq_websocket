#include "../bq_websocket_platform.h"

#define _WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <stdio.h>

#define MAX_CLIENTS 64

typedef struct {
	bqws_socket *ws;
	char name[64];
} client;

static void ws_log(void *user, bqws_socket *ws, const char *line)
{
	printf("> %p: %s\n", ws, line);
}

client clients[MAX_CLIENTS] = { 0 };

static void process_command(client *c, bqws_msg *msg)
{
	if (msg->type != BQWS_MSG_TEXT) {
		bqws_send_text(c->ws, "error Only text messages are supported");
		return;
	}

	char cmd[64];
	char *data = NULL;
	for (size_t i = 0; i + 1 < sizeof(cmd) && msg->data[i]; i++) {
		if (msg->data[i] == ' ') {
			cmd[i] = '\0';
			data = msg->data + i + 1;
			break;
		} else {
			cmd[i] = msg->data[i];
		}
	}

	if (!data) {
		bqws_send_text(c->ws, "error Bad command");
		return;
	}

	size_t len = (msg->data + msg->size) - data;

	if (!strcmp(cmd, "name")) {
		if (len > sizeof(c->name)) {
			bqws_send_text(c->ws, "error Name too long");
			return;
		}
		memcpy(c->name, data, len);

		return;
	}

	if (!strcmp(cmd, "send")) {
		if (!*c->name) {
			bqws_send_text(c->ws, "error Sending message with no name");
			return;
		}

		char prefix[256];
		snprintf(prefix, sizeof(prefix), "msg %s ", c->name);

		for (size_t i = 0; i < MAX_CLIENTS; i++) {
			client *oc = &clients[i];
			if (oc == c || !oc->ws) continue;

			bqws_send_begin(oc->ws, BQWS_MSG_TEXT);
			bqws_send_append_str(oc->ws, prefix);
			bqws_send_append(oc->ws, data, len);
			bqws_send_finish(oc->ws);
		}

		return;
	}

	bqws_send_text(c->ws, "error Unknown command");
}

int main()
{
	bqws_pt_init();

	bqws_pt_listen_opts listen_opts = { 0 };
	listen_opts.port = 4004;
	bqws_pt_server *sv = bqws_pt_listen(&listen_opts);

	for (;;) {
		Sleep(10);

		// Accept new connections
		for (size_t i = 0; i < MAX_CLIENTS; i++) {
			if (clients[i].ws) continue;

			bqws_opts opts = { 0 };
			opts.log_fn = &ws_log;

			bqws_socket *ws = bqws_pt_accept(sv, &opts, NULL);
			if (!ws) break;

			bqws_server_accept(ws, "");
			clients[i].ws = ws;
			clients[i].name[0] = '\0';
		}

		// Update connections
		for (size_t i = 0; i < MAX_CLIENTS; i++) {
			client *c = &clients[i];
			if (!c->ws) continue;

			bqws_update(c->ws);

			bqws_msg *msg;
			while ((msg = bqws_recv(c->ws)) != NULL) {
				process_command(c, msg);
				bqws_free_msg(msg);
			}

			if (bqws_is_closed(c->ws)) {
				bqws_free_socket(c->ws);
				clients[i].ws = NULL;
			}
		}
	}

	return 0;
}
