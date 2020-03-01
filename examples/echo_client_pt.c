#include "../bq_websocket_platform.h"

#include <stdio.h>

#define _WIN32_LEAN_AND_MEAN
#include <Windows.h>

int main(int argc, char **argv)
{
	bqws_pt_init_opts init_opts = { 0 };
	init_opts.ca_filename = "cacert.pem";
	bqws_pt_init(&init_opts);

	bqws_socket *ws = bqws_pt_connect("wss://demos.kaazing.com/echo", NULL, NULL);

	bqws_send_text(ws, "Hello world!");

	bqws_msg *msg = bqws_allocate_msg(ws, BQWS_MSG_TEXT, 4);
	memcpy(msg->data, "Test", 4);
	bqws_send_msg(ws, msg);

	bqws_send_begin(ws, BQWS_MSG_TEXT);
	bqws_send_append_str(ws, "Multi");
	bqws_send_append_str(ws, "Part");
	bqws_send_append_str(ws, "Message");
	bqws_send_finish(ws);

	size_t num_recv = 0;
	size_t timer = 0;
	size_t counter = 0;

	for (;;) {
		bqws_update(ws);
		Sleep(10);

		if (num_recv >= 3) {
			if (timer++ % 200 == 0) {
				counter++;
				char msg[32];
				snprintf(msg, sizeof(msg), "%zu", counter);
				printf("%s... ", msg);
				bqws_send_text(ws, msg);
				bqws_update_io_write(ws);
			}
		}

		bqws_msg *msg;
		while ((msg = bqws_recv(ws)) != NULL) {
			num_recv++;
			printf("-> %s\n", msg->data);
			bqws_free_msg(msg);
		}
	}

	return 0;
}
