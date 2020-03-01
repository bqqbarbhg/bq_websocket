#ifndef BQ_WEBSOCKET_PLATFORM_H_INCLUDED
#define BQ_WEBSOCKET_PLATFORM_H_INCLUDED

#include "bq_websocket.h"

typedef struct bqws_pt_server bqws_pt_server;

typedef struct bqws_pt_init_opts {
	const char *ca_filename;
} bqws_pt_init_opts;

typedef struct bqws_pt_listen_opts {
	bool secure;
	uint16_t port;
	size_t backlog;
} bqws_pt_listen_opts;

// -- Global initialization

bool bqws_pt_init(const bqws_pt_init_opts *opts);
void bqws_pt_shutdown();

// -- Platform socket creation

// Client

bqws_socket *bqws_pt_connect(const char *url, const bqws_opts *opts, const bqws_client_opts *client_opts);
bqws_socket *bqws_pt_connect_url(const bqws_url *url, const bqws_opts *opts, const bqws_client_opts *client_opts);

// Server

bqws_pt_server *bqws_pt_listen(const bqws_pt_listen_opts *pt_opts);
void bqws_pt_free_server(bqws_pt_server *sv);

bqws_socket *bqws_pt_accept(bqws_pt_server *sv, const bqws_opts *opts, const bqws_server_opts *server_opts);

#endif
