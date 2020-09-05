#define _CRT_SECURE_NO_WARNINGS

#include "../bq_websocket.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

size_t file_write(void *user, bqws_socket *ws, const void *data, size_t size)
{
	FILE *f = (FILE*)user;
	return fwrite(data, 1, size, f);
}

int main(int argc, char **argv)
{
	bool server = false;
	if (!strcmp(argv[1], "server")) {
		server = true;
	} else if (!strcmp(argv[1], "client")) {
		server = false;
	} else {
		exit(1);
	}

	FILE *f = fopen(argv[2], "wb");

	bqws_opts opts = { 0 };
	opts.skip_handshake = true;
	opts.io.user = f;
	opts.io.send_fn = &file_write;

	bqws_socket *ws;
	if (server) {
		ws = bqws_new_server(&opts, NULL);
	} else {
		ws = bqws_new_client(&opts, NULL);
	}

	bqws_send_text(ws, "msg1");
	bqws_send_binary(ws, "msg2", 4);
	bqws_send_begin(ws, BQWS_MSG_TEXT);
	bqws_send_append(ws, "ms", 2);
	bqws_send_append(ws, "g3", 2);
	bqws_send_finish(ws);
	bqws_send_begin(ws, BQWS_MSG_BINARY);
	bqws_send_append(ws, "ms", 2);
	bqws_send_append(ws, "g4", 2);
	bqws_send_finish(ws);
	bqws_send_ping(ws, "ping", 4);
	bqws_send_pong(ws, "pong", 4);
	bqws_queue_close(ws, BQWS_CLOSE_NO_REASON, "close", 5);

	for (uint32_t i = 0; i < 5; i++) {
		bqws_update(ws);
	}

	bqws_free_socket(ws);

	fclose(f);

	return 0;
}