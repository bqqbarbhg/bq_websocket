#define _CRT_SECURE_NO_WARNINGS

#include "../../bq_websocket.h"

#include <stdio.h>
#include <stdlib.h>
#ifndef _MSC_VER
#include <unistd.h>
#else
#include <io.h>
#include <fcntl.h>
#endif

char g_buffer[1024*1024];

int main(int argc, char **argv)
{
#ifdef USE_CASE_FILES
	FILE *f = NULL;
	for (uint32_t i = 0; ; i++) {
		char buf[1024];
		snprintf(buf, sizeof(buf), "%s%06u.bin", argv[1], i);
		if (f) fclose(f);
		f = fopen(buf, "rb");
		if (!f) {
			printf("Success! Tested %u cases\n", i);
			return 0;
		}
		size_t size = fread(g_buffer, 1, sizeof(g_buffer), f);
#else
	#ifndef _MSC_VER
	#if defined(__AFL_LOOP)
	while (__AFL_LOOP(10000)) {
	#else
	{
	#endif
		size_t size = (size_t)read(0, g_buffer, sizeof(g_buffer));
	#else
	{
		_setmode(_fileno(stdin), O_BINARY);
		size_t size = fread(g_buffer, 1, sizeof(g_buffer), stdin);
	#endif
#endif

		bqws_socket *ws = bqws_new_server(NULL, NULL);
		bqws_read_from(ws, g_buffer, size);
        bqws_update_state(ws);
		bqws_free_socket(ws);
	}

	return 0;
}

