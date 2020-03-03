#include "test_shared.h"
#include <string.h>

bqws_socket *client;
bqws_socket *server;

static size_t push_send(void *user, bqws_socket *ws, const void *data, size_t size)
{
	bqws_socket *dst = *(bqws_socket**)user;
	return bqws_read_from(dst, data, size);
}

static size_t pull_recv(void *user, bqws_socket *ws, void *data, size_t max_size, size_t min_size)
{
	bqws_socket *src = *(bqws_socket**)user;
	return bqws_write_to(src, data, max_size);
}

int main(int argc, char **argv)
{
	bqws_opts shared_opts = { 0 };
#ifdef TEST_PULL
	shared_opts.io.recv_fn = &pull_recv;
#else
	shared_opts.io.send_fn = &push_send;
#endif
	shared_opts.log_fn = &test_log_fn;
	shared_opts.log_send = true;
	shared_opts.log_recv = true;

	printf("  Client                                    Server\n");

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

	bqws_send_begin(server, BQWS_MSG_TEXT);
	bqws_send_append_str(server, "Hello ");
	bqws_send_append_str(server, "Client");
	bqws_send_finish(server);

	bqws_send_ping(client, "ClientPing", strlen("ClientPing"));
	bqws_send_ping(server, "ServerPing", strlen("ServerPing"));

	size_t big_size = 126;
	size_t huge_size = 65536;

	{
		uint8_t data[128];
		for (size_t i = 0; i < big_size; i++) {
			data[i] = (uint8_t)((((i*i)>>8)+i));
		}
		bqws_send_binary(client, data, big_size);
	}

	{
		bqws_msg *msg = bqws_allocate_msg(server, BQWS_MSG_BINARY, huge_size);
		for (size_t i = 0; i < huge_size; i++) {
			msg->data[i] = (uint8_t)((((i*i)>>16)+i));
		}
		bqws_send_msg(server, msg);
	}

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

	{
		bqws_msg *msg = bqws_recv(client);
		test_check(msg);
		test_check(msg->type == BQWS_MSG_BINARY);
		test_check(msg->size == huge_size);
		for (size_t i = 0; i < huge_size; i++) {
			test_check((uint8_t)msg->data[i] == (uint8_t)((((i*i)>>16)+i)));
		}
		bqws_free_msg(msg);
	}

	{
		bqws_msg *msg = bqws_recv(server);
		test_check(msg);
		test_check(msg->type == BQWS_MSG_BINARY);
		test_check(msg->size == big_size);
		for (size_t i = 0; i < big_size; i++) {
			test_check((uint8_t)msg->data[i] == (uint8_t)((((i*i)>>8)+i)));
		}
		bqws_free_msg(msg);
	}


	test_check(bqws_recv(client) == NULL);
	test_check(bqws_recv(server) == NULL);

	bqws_close(client, (bqws_close_reason)30001, NULL, 0);
	bqws_close(server, (bqws_close_reason)30002, NULL, 0);

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
