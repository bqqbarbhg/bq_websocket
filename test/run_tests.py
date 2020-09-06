#!/usr/bin/env python3

from collections import namedtuple
import tarfile
import os
import sys
import subprocess
import shlex

verbose = "-v" in sys.argv

self_path = os.path.dirname(os.path.abspath(__file__))
root_path = os.path.join(self_path, "..")
build_path = os.path.join(root_path, "build")

if not os.path.exists(build_path):
    print("Creating build directory: {}".format(os.path.abspath(build_path)))
    os.mkdir(build_path)
os.chdir(build_path)

class TestExe:
    def __init__(self, **kwargs):
        self.name = kwargs["name"]
        self.desc = kwargs.get("desc", self.name)
        self.args = kwargs.get("args", [])
        self.sources = kwargs.get("sources", [])
        self.defines = kwargs.get("defines", [])

def extract_tar_gz(name):
    print("Extracting {}".format(name))
    tar = tarfile.open(name)
    tar.extractall()
    tar.close()

def init_vsvars():
    print("=== Setting up MSVC variables ===")
    vswhere_path = r"%ProgramFiles(x86)%/Microsoft Visual Studio/Installer/vswhere.exe"
    vswhere_path = os.path.expandvars(vswhere_path)
    if not os.path.exists(vswhere_path):
        raise EnvironmentError("vswhere.exe not found at: %s", vswhere_path)

    vs_path = os.popen('"{}" -latest -property installationPath'.format(vswhere_path)).read().rstrip()
    vsvars_path = os.path.join(vs_path, "VC\\Auxiliary\\Build\\vcvars64.bat")
    print(".. Using {}".format(vsvars_path))

    output = os.popen('"{}" && set'.format(vsvars_path)).read()
    for line in output.splitlines():
        pair = line.split("=", 1)
        if(len(pair) >= 2):
            os.environ[pair[0]] = pair[1]

def src_path(path):
    return os.path.relpath(os.path.join(root_path, path)).replace('\\', '/')

def run_cmd(args):
    print("$ " + " ".join(shlex.quote(a) for a in args))
    subprocess.check_call(args)

def build_exe(exe):
    if not exe.sources: return
    print("=== Building {} ===".format(exe.name))
    if sys.platform == "win32":
        IGNORE_WARNINGS = ["-wd4100", "-wd4702", "-wd4459"]
        CL_FLAGS = ["-MT", "-nologo", "-O2", "-W4", "-WX", "-Zi"]
        LD_FLAGS = ["-opt:ref", "user32.lib", "gdi32.lib", "shell32.lib"]
        args = ["cl"]
        args += (src_path(s) for s in exe.sources)
        args += IGNORE_WARNINGS
        args += CL_FLAGS
        args += ("-D" + d for d in exe.defines)
        args += ["-link"]
        args += LD_FLAGS
        args += ["-out:{}.exe".format(exe.name)]
        run_cmd(args)
    else:
        IGNORE_WARNINGS = ["-Wno-unused-value"]
        CC_FLAGS = ["-g", "-std=gnu99", "-O2", "-DGNU_SOURCE"]
        LD_FLAGS = ["-lpthread"]
        args = ["clang"]
        args += (src_path(s) for s in exe.sources)
        args += IGNORE_WARNINGS
        args += CC_FLAGS
        args += ("-D" + d for d in exe.defines)
        args += LD_FLAGS
        args += ["-o", exe.name]
        run_cmd(args)

def run_exe(exe):
    print("=== Running {} ===".format(exe.desc))
    if sys.platform == "win32":
        args = ["{}.exe".format(exe.name)]
        args += exe.args
        if verbose: args += ["-v"]
        run_cmd(args)
    else:
        args = ["./{}".format(exe.name)]
        args += exe.args
        if verbose: args += ["-v"]
        run_cmd(args)

TEST_EXES = [
    TestExe(
        name="test_self",
        desc="test_self (push)",
        sources=["bq_websocket.c", "test/test_self.c"],
    ),
    TestExe(
        name="test_self",
        desc="test_self (pull)",
        args=["--pull"],
    ),
    TestExe(
        name="fuzz_client_handshake",
        sources=["bq_websocket.c", "test/fuzz/fuzz_client_handshake.c"],
        defines=["USE_CASE_FILES"],
        args=["fuzz_test_cases/fuzz_"],
    ),
    TestExe(
        name="fuzz_server_handshake",
        sources=["bq_websocket.c", "test/fuzz/fuzz_server_handshake.c"],
        defines=["USE_CASE_FILES"],
        args=["fuzz_test_cases/fuzz_"],
    ),
    TestExe(
        name="fuzz_protocol",
        sources=["bq_websocket.c", "test/fuzz/fuzz_protocol.c"],
        defines=["USE_CASE_FILES"],
        args=["fuzz_test_cases/fuzz_"],
    ),
    TestExe(
        name="example_echo_client_pt",
        sources=["bq_websocket.c", "bq_websocket_platform.c", "examples/echo_client_pt.c"],
        defines=["NO_TLS"],
    ),
]

extract_tar_gz("../test/fuzz/fuzz_test_cases.tar.gz")
if sys.platform == "win32":
    init_vsvars()

for exe in TEST_EXES:
    build_exe(exe)

for exe in TEST_EXES:
    run_exe(exe)

print("=== All tests passed! ===")
