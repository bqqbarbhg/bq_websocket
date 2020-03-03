#pragma once

#include <stdlib.h>
#include <stdio.h>

#include "../bq_websocket.h"

static void test_log_fn(void *user, bqws_socket *ws, const char *line)
{
	const char *name = bqws_get_name(ws);
	printf("%s: %s\n", name, line);
}

static void test_fail(const char *desc, const char *file, long line)
{
	fprintf(stderr, "Fail: %s:%ld: %s\n", file, line, desc);
	exit(1);
}

#define test_check(cond) do { if (!(cond)) test_fail(#cond, __FILE__, __LINE__); } while (0)
