#include "../bq_websocket_platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
	#define _WIN32_LEAN_AND_MEAN
	#include <Windows.h>
	#define os_sleep() Sleep(10)
#elif defined(__EMSCRIPTEN__)
	#include <emscripten.h>
#else
	 #include <unistd.h>
	#define os_sleep() usleep(10000)
#endif

bqws_socket *ws;
size_t num_recv;
size_t timer;
size_t counter;

static void log(void *user, bqws_socket *ws, const char *line)
{
	printf("@@ %s\n", line);
}

static void log_pt_error()
{
	bqws_pt_error err;
	if (bqws_pt_get_error(&err)) {
		char desc[256];
		bqws_pt_get_error_desc(desc, sizeof(desc), &err);
		fprintf(stderr, "%s %s error %d / 0x%08x\n%s\n",
			err.function, bqws_pt_error_type_str(err.type),
			(int)err.data, (unsigned)err.data, desc);
	}
}

void main_loop()
{
	if (!ws) return;

	bqws_update(ws);

	if (num_recv >= 3) {
		if (timer++ % 100 == 0) {
			counter++;
			char msg[32];
			snprintf(msg, sizeof(msg), "%zu", counter);
			printf("%s...\n", msg);
			bqws_send_text(ws, msg);
			bqws_update_io_write(ws);

			if (counter >= 5) {
				bqws_queue_close(ws, BQWS_CLOSE_NORMAL, NULL, 0);
			}
		}
	}

	bqws_msg *msg;
	while ((msg = bqws_recv(ws)) != NULL) {
		num_recv++;
		printf("-> %s\n", msg->data);
		bqws_free_msg(msg);
	}

	if (bqws_is_closed(ws)) {
		bqws_stats stats = bqws_get_stats(ws);
		printf("Sent %zu messages: %zu bytes\n", (size_t)stats.send.total_messages, (size_t)stats.send.total_bytes);
		printf("Received %zu messages: %zu bytes\n", (size_t)stats.recv.total_messages, (size_t)stats.recv.total_bytes);

		bqws_free_socket(ws);
		ws = NULL;

		log_pt_error();
	}
}

int main(int argc, char **argv)
{
	bqws_pt_init_opts init_opts = { 0 };
	init_opts.ca_filename = "cacert.pem";
	if (!bqws_pt_init(&init_opts)) {
		fprintf(stderr, "bqws_pt_init() failed\n");
		log_pt_error();
		return 1;
	}

	bqws_opts opts = { 0 };
	opts.log_fn = &log;

	ws = bqws_pt_connect("wss://demos.kaazing.com/echo", NULL, &opts, NULL);
	if (!ws) {
		fprintf(stderr, "bqws_pt_connect() failed\n");
		log_pt_error();
		return 1;
	}

	bqws_send_text(ws, "Hello world!");

	bqws_msg *msg = bqws_allocate_msg(ws, BQWS_MSG_TEXT, 4);
	memcpy(msg->data, "Test", 4);
	bqws_send_msg(ws, msg);

	bqws_send_begin(ws, BQWS_MSG_TEXT);
	bqws_send_append_str(ws, "Multi");
	bqws_send_append_str(ws, "Part");
	bqws_send_append_str(ws, "Message");
	bqws_send_finish(ws);

#if defined(__EMSCRIPTEN__)
	emscripten_set_main_loop(&main_loop, 60, 1);
#else
	for (;;) {
		os_sleep();
		main_loop();
	}
#endif

	return 0;
}
