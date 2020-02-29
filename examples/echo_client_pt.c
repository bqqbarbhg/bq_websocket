#include "bq_websocket_platform.h"

#include <stdio.h>

#define _WIN32_LEAN_AND_MEAN
#include <Windows.h>

int main(int argc, char **argv)
{
	bqws_pt_init();

	bqws_socket *ws = bqws_pt_connect("ws://demos.kaazing.com/echo", NULL, NULL);

	bqws_send_text(ws, "Hello world!");
	bqws_send_text(ws, "YEET");

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
