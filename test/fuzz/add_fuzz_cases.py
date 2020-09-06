#!/usr/bin/env python3

import os
import re
import sys

fuzz_path = sys.argv[1]

fuzz_files = { }
file_queue = []

RE_FUZZ = re.compile(r"fuzz_(\d+).bin")

for name in os.listdir(fuzz_path):
    path = os.path.join(fuzz_path, name)
    with open(path, 'rb') as f:
        content = f.read()
    m = RE_FUZZ.match(name)
    if m:
        fuzz_files[content] = name
    else:
        file_queue.append((name, content))

for name, content in file_queue:
    existing = fuzz_files.get(content)
    if existing:
        print("{}: Exists as {}".format(name.encode(sys.stdout.encoding, "ignore").decode("utf-8"), existing))
        path = os.path.join(fuzz_path, name)
        os.remove(path)
    else:
        new_name = "fuzz_{:06}.bin".format(len(fuzz_files))
        print("{}: Renaming to {}".format(name.encode(sys.stdout.encoding, "ignore").decode("utf-8"), new_name))
        fuzz_files[content] = new_name
        path = os.path.join(fuzz_path, name)
        new_path = os.path.join(fuzz_path, new_name)
        os.rename(path, new_path)
