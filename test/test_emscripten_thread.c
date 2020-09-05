#include <emscripten.h>
#include <pthread.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "../bq_websocket.h"
#include "../bq_websocket_platform.h"

pthread_t thread;
pthread_mutex_t ws_free_mutex = PTHREAD_MUTEX_INITIALIZER;

bqws_socket *ws;
int counter = 0;

void thread_loop()
{
    pthread_mutex_lock(&ws_free_mutex);
    if (ws) {
        bqws_update(ws);
    }
    pthread_mutex_unlock(&ws_free_mutex);
}

void *thread_entry(void *arg)
{
	emscripten_set_main_loop(&thread_loop, 10, 0);
    return NULL;
}

void main_loop()
{
    if (!ws) return;

    if (bqws_is_closed(ws)) {
        pthread_mutex_lock(&ws_free_mutex);
        bqws_free_socket(ws);
        ws = NULL;
        pthread_mutex_unlock(&ws_free_mutex);
        return;
    }

    counter++;
    if (counter <= 5) {
        char buf[128];
        snprintf(buf, sizeof(buf), "%d!!", counter);
        printf("send> %s\n", buf);
        bqws_send_text(ws, buf);
    }

    bqws_msg *msg;
    while ((msg = bqws_recv(ws)) != NULL) {
        assert(msg->type == BQWS_MSG_TEXT);
        printf("recv> %s\n", msg->data);
        bqws_free_msg(msg);
    }

    if (counter >= 10) {
        bqws_close(ws, BQWS_CLOSE_NORMAL, NULL, 0);
    }
}

static void log(void *user, bqws_socket *ws, const char *line)
{
	printf("@@ %s\n", line);
}

int main(int argc, char **argv)
{
    bqws_pt_init(NULL);

	bqws_opts opts = { 0 };
	opts.log_fn = &log;

    ws = bqws_pt_connect("wss://echo.websocket.org", NULL, &opts, NULL);

    pthread_create(&thread, NULL, &thread_entry, NULL);

	emscripten_set_main_loop(&main_loop, 1, 1);
}
