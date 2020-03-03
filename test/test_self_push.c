#include "test_shared.h"
#include <string.h>

bqws_socket *client;
bqws_socket *server;

static size_t push_send(void *user, bqws_socket *ws, const void *data, size_t size)
{
	bqws_socket *dst = *(bqws_socket**)user;
	bqws_read_from(dst, data, size);
}

int main(int argc, char **argv)
{
	bqws_opts shared_opts = { 0 };
	shared_opts.io.send_fn = &push_send;
	shared_opts.log_fn = &test_log_fn;
	shared_opts.log_send = true;
	shared_opts.log_recv = true;

	{
		bqws_opts opts = shared_opts;
		opts.io.user = &client;
		opts.name = "Server",
		server = bqws_new_server(&opts, NULL);
		test_check(server);
	}

	{
		bqws_opts opts = shared_opts;
		opts.io.user = &server;
		opts.name = "Client",
		client = bqws_new_client(&opts, NULL);
		test_check(client);
	}

	bqws_server_accept(server, NULL);

	bqws_send_text(client, "Hello Server");
	bqws_send_text(server, "Hello Client");

	for (size_t i = 0; i < 10; i++) {
		bqws_update(client);
		bqws_update(server);
	}

	test_check(bqws_get_state(client) == BQWS_STATE_OPEN);
	test_check(bqws_get_state(server) == BQWS_STATE_OPEN);

	{
		bqws_msg *msg = bqws_recv(client);
		test_check(msg);
		test_check(msg->type == BQWS_MSG_TEXT);
		test_check(msg->size == strlen("Hello Client"));
		test_check(!strcmp(msg->data, "Hello Client"));
		bqws_free_msg(msg);
	}

	{
		bqws_msg *msg = bqws_recv(server);
		test_check(msg);
		test_check(msg->type == BQWS_MSG_TEXT);
		test_check(msg->size == strlen("Hello Server"));
		test_check(!strcmp(msg->data, "Hello Server"));
		bqws_free_msg(msg);
	}

	test_check(bqws_recv(client) == NULL);
	test_check(bqws_recv(server) == NULL);

	bqws_close(client, (bqws_close_reason)30001, NULL, 0);
	bqws_close(server, (bqws_close_reason)30002, BQWS_CLOSE_NORMAL, NULL, 0);

	for (size_t i = 0; i < 10; i++) {
		bqws_update(client);
		bqws_update(server);
	}

	test_check(bqws_get_error(client) == BQWS_OK);
	test_check(bqws_get_error(server) == BQWS_OK);

	test_check((int)bqws_get_peer_close_reason(client) == 30002);
	test_check((int)bqws_get_peer_close_reason(server) == 30001);

	bqws_free_socket(client);
	bqws_free_socket(server);

	return 0;
}
