#include "../bq_websocket_net.h"
#include <Windows.h>

static bool on_message(void *user, bqws_socket *ws, bqws_msg *msg)
{
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

	return true;
}

int main(int argc, char **argv)
{
	bqws_net_init(NULL);

	bqws_opts opts = { 0 };
	opts.message_fn = &on_message;

	bqws_server_opts server_opts = { 0 };

	bqws_net_server *server = bqws_net_listen(4004, &opts, &server_opts);

	for (;;) {
		bqws_net_update();

		bqws_socket *ws = bqws_net_accept(server);

		Sleep(100);
	}

	return 0;
}
