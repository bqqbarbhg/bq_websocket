#include "../bq_websocket_platform.h"

#include <stdio.h>

#define _WIN32_LEAN_AND_MEAN
#include <Windows.h>

int main(int argc, char **argv)
{
	bqws_pt_init();

	bqws_socket *ws = bqws_pt_connect("ws://demos.kaazing.com/echo", NULL, NULL);

	bqws_send_text(ws, "Hello world!");

	bqws_msg *msg = bqws_allocate_msg(ws, BQWS_MSG_TEXT, 4);
	memcpy(msg->data, "Test", 4);
	bqws_send_msg(ws, msg);

	bqws_send_begin(ws, BQWS_MSG_TEXT);
	bqws_send_append_str(ws, "Multi");
	bqws_send_append_str(ws, "Part");
	bqws_send_append_str(ws, "Message");
	bqws_send_finish(ws);

	for (;;) {
		bqws_update(ws);
		Sleep(10);

		bqws_msg *msg;
		while ((msg = bqws_recv(ws)) != NULL) {
			printf("-> %s\n", msg->data);
			bqws_free_msg(msg);
		}
	}

	return 0;
}
