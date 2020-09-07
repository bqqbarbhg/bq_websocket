#!/usr/bin/env python3

from collections import namedtuple
import tarfile
import os
import sys
import subprocess
import shlex
import re
import shutil
import random
import http.server
import http.client
import itertools
import argparse

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    p.add_argument("--emscripten", action="store_true", help="Run tests in the Emscripten environment")
    p.add_argument("--no-gcc", action="store_true", help="Skip building GCC")
    p.add_argument("--test", "-t", nargs="*", default=[], action="append", help="List of tests to run")
    p.add_argument("--list", action="store_true", help="List available tests")
    p.add_argument("--skip-build", action="store_true", help="Skip building from sources (just run tests)")
    p.add_argument("--skip-node", action="store_true", help="Skip running Node.js tests")
    p.add_argument("--skip-html", action="store_true", help="Skip running HTML tests")
    p.add_argument("--skip-install", action="store_true", help="Skip running install/copy process")
    return p.parse_args()

argv = parse_args()
verbose = argv.verbose
emscripten = argv.emscripten
tests = set(itertools.chain(*argv.test))

def test_enabled(name):
    return not tests or name in tests

self_path = os.path.dirname(os.path.abspath(__file__))
root_path = os.path.join(self_path, "..")
build_path = os.path.join(root_path, "build")

if not os.path.exists(build_path):
    print("Creating build directory: {}".format(os.path.abspath(build_path)), flush=True)
    os.mkdir(build_path)
os.chdir(build_path)

class TestExe:
    def __init__(self, **kwargs):
        self.name = kwargs["name"]
        self.desc = kwargs.get("desc", self.name)
        self.args = kwargs.get("args", [])
        self.sources = kwargs.get("sources", [])
        self.defines = kwargs.get("defines", [])
        self.use_network = kwargs.get("use_network", False)
        self.use_asyncify = kwargs.get("use_asyncify", False)
        self.html_test = kwargs.get("html_test", None)
        self.html_args = kwargs.get("html_args", [])
        self.help = kwargs.get("help", "")

def extract_tar_gz(name):
    print("Extracting {}".format(name), flush=True)
    tar = tarfile.open(name)
    tar.extractall()
    tar.close()

def init_vsvars():
    print("=== Setting up MSVC variables ===", flush=True)
    vswhere_path = r"%ProgramFiles(x86)%/Microsoft Visual Studio/Installer/vswhere.exe"
    vswhere_path = os.path.expandvars(vswhere_path)
    if not os.path.exists(vswhere_path):
        raise EnvironmentError("vswhere.exe not found at: %s", vswhere_path)

    vs_path = os.popen('"{}" -latest -property installationPath'.format(vswhere_path)).read().rstrip()
    vsvars_path = os.path.join(vs_path, "VC\\Auxiliary\\Build\\vcvars64.bat")
    print(".. Using {}".format(vsvars_path), flush=True)

    output = os.popen('"{}" && set'.format(vsvars_path)).read()
    for line in output.splitlines():
        pair = line.split("=", 1)
        if(len(pair) >= 2):
            os.environ[pair[0]] = pair[1]

local_file_server_port = 0
server_process = None
def start_server():
    global local_file_server_port
    global server_process
    local_file_server_port = random.randint(10000,60000)
    print("=== Starting local file server (port {}) ===".format(local_file_server_port))
    args = [os.path.join("node_modules", ".bin", "serve")]
    args += ["--no-clipboard", "--no-compression"]
    args += ["-l", str(local_file_server_port)]
    print("$ " + " ".join(shlex.quote(a) for a in args) + " &", flush=True)
    null = open(os.devnull, "w")
    shell = sys.platform == "win32"
    server_process = subprocess.Popen(args, shell=shell, stdout=null)

def check_server():
    print("=== Checking connection to local file server (port {}) ===".format(local_file_server_port))
    conn = http.client.HTTPConnection("localhost", local_file_server_port)
    conn.request("HEAD", "/")
    resp = conn.getresponse()
    assert resp.status == 200

def close_server():
    if server_process:
        print("=== Terminating local server (port {}) ===".format(local_file_server_port))
        server_process.terminate()

def src_path(path):
    return os.path.relpath(os.path.join(root_path, path)).replace('\\', '/')

def run_cmd(args):
    print("$ " + " ".join(shlex.quote(a) for a in args), flush=True)
    shell = sys.platform == "win32"
    subprocess.check_call(args, shell=shell, timeout=240)

def extract_readme_examples():
    print("=== Extracting README examples ===")
    RE_EXAMPLE = re.compile(r"\s*\[//\]:\s*# \(example\s+(\w+\.c)\s*\)\s*")
    with open("../README.md") as f:
        file_name = None
        lines = []
        for line in f:
            line = line.rstrip()
            m = RE_EXAMPLE.match(line)
            if m:
                file_name = m.group(1)
                lines = []
                continue
            if file_name:
                if line.strip() == "```c":
                    continue
                elif line.strip() == "```":
                    print("Found: {} ({} lines)".format(file_name, len(lines)))
                    with open(file_name, "w") as wf:
                        wf.write("\n".join(lines))
                        wf.write("\n")
                    lines = []
                    file_name = None
                else:
                    lines.append(line)


def copy_cpp_files():
    print("=== Copying C++ variants ===")
    shutil.copyfile("../bq_websocket.c", "bq_websocket.cpp")
    shutil.copyfile("../bq_websocket_platform.c", "bq_websocket_platform.cpp")
    shutil.copyfile("../bq_websocket.h", "bq_websocket.h")
    shutil.copyfile("../bq_websocket_platform.h", "bq_websocket_platform.h")
    shutil.copyfile("readme_client_usage.c", "readme_client_usage.cpp")

def setup_node_env():
    print("=== Setting up Node.js environment ===")
    node_env_path = "../test/node_env"
    for f in os.listdir(node_env_path):
        f_path = os.path.join(node_env_path, f)
        shutil.copyfile(f_path, f)

    run_cmd(["npm", "install", "-y"])

def build_exe(exe):
    if not exe.sources: return
    print("=== Building {} ===".format(exe.name), flush=True)
    if sys.platform == "win32" and not emscripten:
        IGNORE_WARNINGS = ["-wd4100", "-wd4702", "-wd4459"]
        CL_FLAGS = ["-MT", "-nologo", "-O2", "-W4", "-WX", "-Zi"]
        LD_FLAGS = ["-opt:ref", "user32.lib", "gdi32.lib", "shell32.lib"]
        args = ["cl"]
        args += (src_path(s) for s in exe.sources)
        args += IGNORE_WARNINGS
        args += CL_FLAGS
        args += ("-D" + d for d in exe.defines)
        args += ["-I", ".."]
        args += ["-link"]
        args += LD_FLAGS
        args += ["-out:{}.exe".format(exe.name)]
        run_cmd(args)
    else:
        IGNORE_WARNINGS = ["-Wno-unused-value"]
        is_cpp = any(s.endswith(".cpp") for s in exe.sources)
        CC_FLAGS = ["-g", "-O2", "-DGNU_SOURCE", "-Wall"]

        if emscripten:
            ccs = ["emcc"]
        elif argv.no_gcc:
            ccs = ["clang"]
        else:
            ccs = ["gcc", "clang"]

        if emscripten:
            exts = [".js", "_html.html"]
        else:
            exts = [""]

        for cc, ext in itertools.product(ccs, exts):
            args = [cc]
            args += (src_path(s) for s in exe.sources)
            args += IGNORE_WARNINGS
            args += CC_FLAGS
            if is_cpp:
                args += ["-std=c++11"]
            else:
                args += ["-std=gnu99"]
            args += ("-D" + d for d in exe.defines)
            args += ["-I.."]
            if emscripten:
                # TODO: Couldn't get Node.js threads to work..
                if ext == ".html":
                    args += ["-pthread"]
            else:
                args += ["-lpthread"]
            if emscripten:
                args += ["-s", "NODERAWFS=1"]
            if emscripten and exe.use_asyncify:
                args += ["-s", "ASYNCIFY"]
            if sys.platform == "darwin" and exe.use_network:
                args += ["-framework", "CoreFoundation"]
                args += ["-framework", "CFNetwork"]
            if emscripten:
                args += ["-o", exe.name + ext]
            else:
                args += ["-o", exe.name + ext]
            run_cmd(args)

def run_exe(exe):
    print("=== Running {} ===".format(exe.desc), flush=True)
    if emscripten:
        if exe.use_asyncify:
            print("TODO: Skipped Node.js run, cannot call C if using -S ASYNCIFY (?)")
            return

        # TODO: Asyncify can't call C functions ?!?!
        args = ["node"]
        args += [exe.name + ".js"]
        args += exe.args
        if verbose: args += ["-v"]

        if not argv.skip_node:
            run_cmd(args)

        if exe.html_test:
            args = ["node", exe.html_test, str(local_file_server_port), exe.name + "_html.html"]
            args += exe.html_args

            if not argv.skip_html:
                run_cmd(args)

    elif sys.platform == "win32":
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
        desc="test_self_push",
        help="Send messages between two bq_websocket instances (push to client)",
        sources=["bq_websocket.c", "test/test_self.c"],
    ),
    TestExe(
        name="test_self",
        desc="test_self_pull",
        help="Send messages between two bq_websocket instances (pull from client)",
        sources=["bq_websocket.c", "test/test_self.c"],
        args=["--pull"],
    ),
    TestExe(
        name="fuzz_client_handshake",
        help="Run fuzzed test cases through the client handshake parser",
        sources=["bq_websocket.c", "test/fuzz/fuzz_client_handshake.c"],
        defines=["USE_CASE_FILES"],
        args=["fuzz_test_cases/fuzz_"],
    ),
    TestExe(
        name="fuzz_server_handshake",
        help="Run fuzzed test cases through the server handshake parser",
        sources=["bq_websocket.c", "test/fuzz/fuzz_server_handshake.c"],
        defines=["USE_CASE_FILES"],
        args=["fuzz_test_cases/fuzz_"],
    ),
    TestExe(
        name="fuzz_protocol",
        help="Run fuzzed test cases through the WebSocket protocol parser",
        sources=["bq_websocket.c", "test/fuzz/fuzz_protocol.c"],
        defines=["USE_CASE_FILES"],
        args=["fuzz_test_cases/fuzz_"],
    ),
    TestExe(
        name="example_echo_client_pt",
        help="Use the echo client example to send/receive messages",
        sources=["bq_websocket.c", "bq_websocket_platform.c", "examples/echo_client_pt.c"],
        defines=["NO_TLS"],
        use_network=True,
        html_test="puppeteer_match_log.js",
        html_args=["../test/puppeteer_logs/example_echo_client_pt.txt"],
    ),
    TestExe(
        name="readme_client_usage",
        help="Use the client example embedded in README.md",
        sources=["bq_websocket.c", "bq_websocket_platform.c", "build/readme_client_usage.c"],
        use_network=True,
        use_asyncify=True,
        html_test="puppeteer_match_log.js",
        html_args=["../test/puppeteer_logs/readme_client_usage_log.txt"],
    ),
    TestExe(
        name="readme_client_usage",
        help="Use the client example embedded in README.md (build bq_websocket/platform.c using C++)",
        desc="readme_client_usage_cpp",
        sources=["build/bq_websocket.cpp", "build/bq_websocket_platform.cpp", "build/readme_client_usage.cpp"],
        use_network=True,
        use_asyncify=True,
    ),
]

def run_main():
    if argv.list:
        for exe in TEST_EXES:
            print("{:<25} {}".format(exe.desc + ":", exe.help))
        return

    if not argv.skip_install:
        extract_tar_gz("../test/fuzz/fuzz_test_cases.tar.gz")
        extract_readme_examples()
        copy_cpp_files()

    if emscripten and not argv.skip_install:
        setup_node_env()

    if emscripten:
        start_server()

    if sys.platform == "win32" and not emscripten:
        init_vsvars()

    if not argv.skip_build:
        for exe in TEST_EXES:
            if not test_enabled(exe.desc): continue
            build_exe(exe)

    if emscripten:
        check_server()

    for exe in TEST_EXES:
        if not test_enabled(exe.desc): continue
        run_exe(exe)

    close_server()

    print("=== All tests passed! ===", flush=True)

if __name__ == "__main__":
    run_main()
