#include "../bq_websocket.h"
#include "../bq_websocket_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
	#define _WIN32_LEAN_AND_MEAN
	#include <Windows.h>
	#define os_sleep() Sleep(10)
#else
	 #include <unistd.h>
	#define os_sleep() usleep(10000)
#endif

#define MAX_CLIENTS 128

bqws_socket *clients[MAX_CLIENTS];

int main(int argc, char **argv)
{
	uint16_t port = 8008;
	bool all_caps = false;

	// Parse arguments
	for (int argi = 1; argi < argc; argi++) {
		if (!strcmp(argv[argi], "--port") && argi + 1 < argc) {
			port = (uint16_t)atoi(argv[++argi]);
		} else if (!strcmp(argv[argi], "--all-caps")) {
			all_caps = true;
		}
	}

	// Global platform initialization
	bqws_pt_init(NULL);

	// Start the listen server
	bqws_pt_listen_opts listen_opts = { 0 };
	listen_opts.port = port;
	bqws_pt_server *server = bqws_pt_listen(&listen_opts);

	for (;;) {

		// Accept new clients with default options
		bqws_socket *new_client_ws = bqws_pt_accept(server, NULL, NULL);
		if (new_client_ws) {

			// Find a slot for the client
			bool found_slot = false;
			for (size_t i = 0; i < MAX_CLIENTS; i++) {
				if (!clients[i]) {
					clients[i] = new_client_ws;
					found_slot = true;
				}
			}

			// If we didn't find a slot free the socket
			if (!found_slot) {
				bqws_free_socket(new_client_ws);
			}
		}

		// Update existing sockets
		for (size_t i = 0; i < MAX_CLIENTS; i++) {
			bqws_socket *ws = clients[i];
			if (!ws) continue;
			bqws_update(ws);

			if (bqws_is_closed(ws)) {

				// Free the socket and client slot
				bqws_free_socket(ws);
				clients[i] = NULL;

			} else if (bqws_is_connecting(ws)) {

				// Poll until we get `client_opts` from the handshake
				bqws_client_opts *client_opts = bqws_server_get_client_opts(ws);
				if (client_opts) {
					// We require the 'echo' protocol
					bool found_protocol = false;
					for (size_t i = 0; i < client_opts->num_protocols; i++) {
						if (!strcmp(client_opts->protocols[i], "echo")) {
							found_protocol = true;
							break;
						}
					}
					if (found_protocol) {
						bqws_server_accept(ws, "echo");
					} else {
						bqws_server_reject(ws);
					}
				}

			} else {

				// Serve incoming messages
				bqws_msg *msg;
				while (msg = bqws_recv(ws)) {
					if (msg->type == BQWS_MSG_TEXT) {
						// We can modify and even re-use the message buffer to send back!

						if (all_caps) {
							for (size_t i = 0; i < msg->size; i++) {
								msg->data[i] = (char)toupper(msg->data[i]);
							}
						}

						bqws_send_msg(ws, msg);
					} else {
						bqws_close(ws, BQWS_CLOSE_UNSUPPORTED_TYPE, NULL, 0);
						bqws_free_msg(msg);
					}
				}

			}
			
		}

		os_sleep();
	}

}
