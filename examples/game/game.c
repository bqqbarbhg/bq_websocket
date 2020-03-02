#include "sokol_app.h"
#include "sokol_args.h"
#include "sokol_gfx.h"
#include "sokol_gl.h"

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <math.h>

#include "../../bq_websocket.h"
#include "../../bq_websocket_platform.h"

#ifdef _WIN32

#define _WIN32_LEAN_AND_MEAN
#include <Windows.h>

static void log_debug(const char *fmt, ...)
{
	char buf[2048];

	va_list args;
	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	OutputDebugStringA(buf);
}

#else

#define log_debug(...) fprintf(stderr, __VA_ARGS__)

#endif

static void log_bqws_pt_error()
{
	bqws_pt_error err;
	if (bqws_pt_get_error(&err)) {
		char buf[2048];
		bqws_pt_get_error_desc(buf, sizeof(buf), &err);

		log_debug("Failed to host: %s %s error %d / 0x%08x: %s\n",
			err.function, bqws_pt_error_type_str(err.type), (int)err.data, (uint32_t)err.data, buf);
	}
}

// -- Generic definitions

bool key_down(sapp_keycode code);

#define MAX_CLIENTS 8

typedef struct {
	float x, y;
} vec2;

typedef enum {
	MSG_INIT,
	MSG_UPDATE,
	MSG_CLIENT_UPDATE,
	MSG_LAST = 0x7fffffff,
} msg_type;

typedef struct {
	msg_type type;
} msg_base;

typedef struct {
	msg_base base;
	uint32_t player_index;
} msg_init;

typedef struct {
	bool active;
	vec2 pos;
} update_player;

typedef struct {
	msg_base base;
	update_player players[MAX_CLIENTS];
} msg_update;

typedef struct {
	msg_base base;
	vec2 pos;
} msg_client_update;

// -- Server

typedef struct {
	bool active;
	bqws_socket *ws;
	vec2 pos;
} client;

typedef struct {
	bqws_pt_server *server;
	client clients[MAX_CLIENTS];
} server;

server *g_server = NULL;

server *server_init()
{
	server *s = malloc(sizeof(server));
	assert(s);
	memset(s, 0, sizeof(server));

	bqws_pt_listen_opts opts = { 0 };
	opts.port = (uint16_t)atoi(sargs_value_def("port", "4004"));
	s->server = bqws_pt_listen(&opts);
	if (!s->server) {
		log_bqws_pt_error();
		free(s);
		return NULL;
	}

	return s;
}

void server_msg(server *s, client *c, msg_base *base, size_t size)
{
	if (base->type == MSG_CLIENT_UPDATE) {
		msg_client_update *msg = (msg_client_update*)base;
		assert(size == sizeof(msg_client_update));
		c->pos = msg->pos;
	} else {
		assert(0);
	}
}

void server_update(server *s)
{
	// Accept new clients
	for (size_t i = 0; i < MAX_CLIENTS; i++) {
		client *c = &s->clients[i];
		if (c->active) continue;

		bqws_client_opts filter = {
			.protocols[0] = "game",
			.num_protocols = 1,
		};
		bqws_server_opts opts = {
			.verify_filter = &filter,
		};

		bqws_socket *ws = bqws_pt_accept(s->server, NULL, &opts);
		if (!ws) break;

		{
			msg_init msg;
			msg.base.type = MSG_INIT;
			msg.player_index = (uint32_t)i;
			bqws_send_binary(ws, &msg, sizeof(msg));
		}

		log_debug("Client joined: %zu\n", i);
		c->active = true;
		c->ws = ws;
	}

	// Update active clients
	for (size_t i = 0; i < MAX_CLIENTS; i++) {
		client *c = &s->clients[i];
		if (!c->active) continue;

		bqws_update(c->ws);

		bqws_msg *msg;
		while ((msg = bqws_recv(c->ws)) != NULL) {
			assert(msg->type == BQWS_MSG_BINARY);
			server_msg(s, c, (msg_base*)msg->data, msg->size);
			bqws_free_msg(msg);
		}

		if (bqws_is_closed(c->ws)) {
			log_debug("Client left: %zu\n", i);
			bqws_free_socket(c->ws);
			memset(c, 0, sizeof(client));
		}
	}

	// Send current state to clients
	{
		msg_update msg;
		msg.base.type = MSG_UPDATE;

		for (size_t i = 0; i < MAX_CLIENTS; i++) {
			client *c = &s->clients[i];
			update_player *up = &msg.players[i];

			up->active = c->active;
			up->pos = c->pos;
		}

		for (size_t i = 0; i < MAX_CLIENTS; i++) {
			client *c = &s->clients[i];
			if (!c->active) continue;

			bqws_send_binary(c->ws, &msg, sizeof(msg));

			bqws_update_io_write(c->ws);
		}
	}
}

void server_cleanup(server *s)
{
	for (size_t i = 0; i < MAX_CLIENTS; i++) {
		if (s->clients[i].ws) {
			bqws_free_socket(s->clients[i].ws);
		}
	}

	bqws_pt_free_server(s->server);
	free(s);
}

// -- Client / game

typedef struct {
	bool active;
	bool is_local;
	vec2 pos;
	vec2 vel;
} player;

typedef struct {
	bqws_socket *ws;
	player players[MAX_CLIENTS];
	int local_index;
} game;

game g_game;

void game_init()
{
	bqws_pt_init(NULL);

	if (sargs_boolean("server")) {
		g_server = server_init();
	}

	const char *url = sargs_value_def("url", "ws://localhost:4004");

	game *g = &g_game;
	g->local_index = -1;

	bqws_client_opts opts = {
		.protocols[0] = "game",
		.num_protocols = 1,
	};
	g->ws = bqws_pt_connect(url, NULL, NULL, &opts);
	if (!g->ws) {
		log_bqws_pt_error();
		assert(0);
	}
}

void game_msg(game *g, msg_base *base, size_t size)
{
	if (base->type == MSG_INIT) {
		msg_init *msg = (msg_init*)base;
		assert(size == sizeof(msg_init));
		assert(g->local_index < 0);

		g->local_index = (int)msg->player_index;

		player *p = &g->players[g->local_index];
		p->active = true;
		p->is_local = true;
	} else if (base->type == MSG_UPDATE) {
		msg_update *msg = (msg_update*)base;
		assert(size == sizeof(msg_update));

		for (size_t i = 0; i < MAX_CLIENTS; i++) {
			update_player *up = &msg->players[i];
			player *p = &g->players[i];

			if (!p->is_local) {
				p->active = up->active;
				p->pos = up->pos;
			}
		}

	} else {
		printf("Bad message type: %d\n", base->type);
		assert(0);
	}
}

void game_update(game *g, float dt)
{
	assert(g->local_index >= 0);
	player *p = &g->players[g->local_index];
	assert(p->is_local);

	vec2 move = { 0, 0 };
	if (key_down(SAPP_KEYCODE_LEFT))  move.x -= 1.0f;
	if (key_down(SAPP_KEYCODE_RIGHT)) move.x += 1.0f;
	if (key_down(SAPP_KEYCODE_DOWN))  move.y -= 1.0f;
	if (key_down(SAPP_KEYCODE_UP))    move.y += 1.0f;

	float move_len = sqrtf(move.x*move.x + move.y*move.y);
	if (move_len > 1.0f) {
		move.x /= move_len;
		move.y /= move_len;
	}

	float speed = 128.0f * dt;
	p->vel.x += move.x * speed;
	p->vel.y += move.y * speed;

	float drag = 8.0f * dt;
	p->vel.x -= p->vel.x * drag;
	p->vel.y -= p->vel.y * drag;

	p->pos.x += p->vel.x * dt;
	p->pos.y += p->vel.y * dt;
}

void game_render(game *g)
{
	{
		int w = sapp_width();
		int h = sapp_height();
		float aspect = (float)w / (float)h;
		float scale = 8.0f;

		sgl_matrix_mode_projection();
		sgl_load_identity();
		sgl_ortho(-aspect * scale, +aspect * scale, -scale, +scale, -1.0f, 1.0f);
	}

	sgl_begin_quads();

	for (size_t i = 0; i < MAX_CLIENTS; i++) {
		player *p = &g->players[i];
		if (!p->active) continue;

		float size = 0.5f;
		if (p->is_local) {
			sgl_c3f(1.0f, 1.0f, 1.0f);
		} else {
			sgl_c3f(1.0f, 0.0f, 0.0f);
		}

		sgl_v2f(p->pos.x - size, p->pos.y - size);
		sgl_v2f(p->pos.x + size, p->pos.y - size);
		sgl_v2f(p->pos.x + size, p->pos.y + size);
		sgl_v2f(p->pos.x - size, p->pos.y + size);
	}

	sgl_end();
}

void game_frame(float dt)
{
	if (g_server) {
		server_update(g_server);
	}

	game *g = &g_game;

	// Disconnected
	if (!g->ws) return;

	bqws_update(g->ws);

	bqws_msg *msg;
	while ((msg = bqws_recv(g->ws)) != NULL) {
		assert(msg->type == BQWS_MSG_BINARY);
		game_msg(g, (msg_base*)msg->data, msg->size);
		bqws_free_msg(msg);
	}

	if (bqws_is_closed(g->ws)) {
		log_debug("Disconnected\n");
		bqws_free_socket(g->ws);
		g->ws = NULL;
		return;
	}

	// Still connecting
	if (g->local_index < 0) return;

	// -- Update

	game_update(g, dt);
	game_render(g);

	// Send update to server
	{
		player *p = &g->players[g->local_index];

		msg_client_update msg;
		msg.base.type = MSG_CLIENT_UPDATE;
		msg.pos = p->pos;
		bqws_send_binary(g->ws, &msg, sizeof(msg));
	}

	// Flush messages
	bqws_update_io_write(g->ws);
}

void game_cleanup()
{
	if (g_server) {
		server_cleanup(g_server);
	}

	game *g = &g_game;
	bqws_free_socket(g->ws);

	bqws_pt_shutdown();
}
