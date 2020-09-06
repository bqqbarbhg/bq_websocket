#!/usr/bin/env python3

import os
import re
from re import finditer
import sys
from collections import namedtuple

self_path = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.abspath(os.path.join(self_path, "../bq_websocket.c"))

RE_MUTEX_LOCK = re.compile(r"bqws_mutex_lock\((?:\(bqws_mutex\*\))?&ws->(\w+)\.mutex\);")
RE_MUTEX_UNLOCK = re.compile(r"bqws_mutex_unlock\((?:\(bqws_mutex\*\))?&ws->(\w+)\.mutex\);")
RE_ASSERT_LOCKED = re.compile(r"bqws_assert_locked\(&ws->(\w+)\.mutex\);")
RE_NO_MUTEX = re.compile(r"no-mutex\((\w+)\).*")
RE_ACCESS = re.compile(r"ws->(\w+)\.")
RE_FUNC = re.compile(r"\w+.*\W+(\w+)\(.*")

EnteredMutex = namedtuple("EnteredMutex", "indent lineno asserted")

mutex_names = { "io", "state", "alloc", "partial" }

ignore_functions = { "bqws_new_client", "bqws_new_server", "ws_new_socket", "bqws_free_socket" }

entered_mutexes = { }
ignored_mutexes = { }

num_sections = 0
num_accesses = 0
num_ignored = 0

current_func = None

def fail(message):
    print(message, file=sys.stderr)
    exit(1)

with open(src_path) as f:
    lineno = 0
    for line in f:
        lineno += 1
        indent = 0
        while indent < len(line) and line[indent] == '\t':
            indent += 1
        
        line = line.strip()

        # Remove expired ignored mutexes
        ignored_mutexes = { k: v for k, v in ignored_mutexes.items() if v >= lineno - 1 }

        # Skip mutex init/free
        if indent == 0:
            m = RE_FUNC.match(line)
            if m:
                current_func = m.group(1)
                continue

        if current_func in ignore_functions:
            continue

        m = RE_MUTEX_LOCK.match(line)
        if m:
            mutex = m.group(1)
            if mutex not in mutex_names: continue
            em = entered_mutexes.get(mutex)
            if em:
                fail("Potential deadlock of {}: Entered at lines {} and {}".format(mutex, em.lineno, lineno))
            entered_mutexes[mutex] = EnteredMutex(indent, lineno, False)
            num_sections += 1
            continue

        m = RE_MUTEX_UNLOCK.match(line)
        if m:
            mutex = m.group(1)
            if mutex not in mutex_names: continue
            em = entered_mutexes.get(mutex)
            if not em:
                fail("Exiting non-entered mutex {} at line {}".format(mutex, lineno))
            if em.asserted:
                fail("Unlocking an asserted mutex at line {}".format(lineno))
            if em.indent == indent:
                del entered_mutexes[mutex]
            continue

        m = RE_ASSERT_LOCKED.match(line)
        if m:
            mutex = m.group(1)
            if mutex not in mutex_names: continue
            if indent != 1:
                fail("bqws_assert_locked() not at top-level on line {}".format(lineno))
            em = entered_mutexes.get(mutex)
            if em:
                fail("Potential deadlock of {}: Entered at lines {} and {}".format(mutex, em.lineno, lineno))
            entered_mutexes[mutex] = EnteredMutex(indent, lineno, True)
            continue

        # Remove all asserted mutexes at function end
        if line == "}" and indent == 0:
            entered_mutexes = { k: v for k, v in entered_mutexes.items() if not v.asserted }
            continue

        for m in RE_NO_MUTEX.finditer(line):
            mutex = m.group(1)
            if mutex not in mutex_names: continue
            ignored_mutexes[mutex] = lineno

        for m in RE_ACCESS.finditer(line):
            mutex = m.group(1)
            if mutex not in mutex_names: continue
            num_accesses += 1
            if mutex in ignored_mutexes:
                num_ignored += 1
                continue
            if mutex not in entered_mutexes:
                fail("Accessing {} at line {} outside of a mutex:\n{}".format(mutex, lineno, line))

if entered_mutexes:
    unclosed = ", ".join(f"{name} (line {em.lineno})" for name, em in entered_mutexes.items())
    fail(f"File ended with unclosed mutexes: {unclosed}")

num_protected = num_accesses - num_ignored
print("SUCCESS: {} mutex sections protecting {} accesses! {} explicit 'no-mutex' accesses.".format(num_sections, num_protected, num_ignored))
