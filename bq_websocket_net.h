#ifndef BQ_WEBSOCKET_NET_H_INCLUDED
#define BQ_WEBSOCKET_NET_H_INCLUDED

#include "bq_websocket.h"

typedef struct bqws_net_server bqws_net_server;

bqws_socket *bqws_net_connect(const char *url, const bqws_opts *opts, const bqws_client_opts *client_opts);

bqws_net_server *bqws_net_listen(uint16_t port, const bqws_opts *opts, const bqws_server_opts *server_opts);
void bqws_net_free_server(bqws_net_server *s);

bqws_socket *bqws_net_accept(bqws_net_server *s);

typedef struct bqws_net_opts {

	// Maximum concurrent threads
	// default: number of logical processors
	size_t max_threads;

} bqws_net_opts;

bool bqws_net_init(const bqws_net_opts *opts);
void bqws_net_shutdown();

void bqws_net_update();

#endif
