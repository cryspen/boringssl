#! /usr/bin/env python3

import os
import argparse
import pathlib
import platform
import shutil
import subprocess
import sys


def shell(command, expect=0, cwd=None, env={}):
    subprocess_stdout = subprocess.DEVNULL

    print("Env:", env)
    print("Command: ", end="")
    for i, word in enumerate(command):
        if i == 4:
            print("'{}' ".format(word), end="")
        else:
            print("{} ".format(word), end="")

    print("\nDirectory: {}".format(cwd))

    os_env = os.environ
    os_env.update(env)

    ret = subprocess.run(command, cwd=cwd, env=os_env)
    if ret.returncode != expect:
        raise Exception("Error {}. Expected {}.".format(ret, expect))


def cwd():
    return os.path.dirname(os.path.realpath(__file__))


def join_path(a, *p):
    return os.path.join(a, *p)


def rm(file):
    if os.path.isfile(file):
        os.remove(file)
    else:
        shutil.rmtree(file, ignore_errors=True)


class updateAction(argparse.Action):
    def __call__(self, parser, args, values, option_string=None) -> None:
        if args.libcrux is None and args.rev is None:
            parser.print_help(sys.stderr)
            sys.exit(1)

        if args.rev:
            print("Git revisions are not implemented yet.\nUse --libcrux for now.")
            sys.exit(1)

        libcrux_path = args.libcrux
        libcrux_path = join_path(libcrux_path, "libcrux-ml-kem", "c")
        src_dst_path = join_path(cwd(), "src")
        include_dst_path = join_path(cwd(), "include")

        def copy_dir(directory, src=".", dst="."):
            # print(f"Copying {libcrux_path}/{directory} with src={src} and dst={dst}")
            src = join_path(libcrux_path, src, directory)
            dest = join_path(cwd(), dst, directory)
            shutil.copytree(src, dest)

        # Clean existing build
        rm(join_path(cwd(), "karamel"))
        rm(join_path(cwd(), "include"))
        rm(join_path(cwd(), "src"))

        # Copy karamel
        copy_dir("karamel")

        # Setup directories
        # - include/intrinsics
        # - src/
        pathlib.Path(join_path(include_dst_path, "intrinsics")).mkdir(
            parents=True, exist_ok=True
        )
        pathlib.Path(src_dst_path).mkdir(parents=True, exist_ok=True)

        # Header
        for file in os.listdir(libcrux_path):
            if file.endswith(".h"):
                # print(
                #     f"Copy {join_path(libcrux_path, file)} to ",
                #     join_path(include_dst_path, os.path.basename(file)),
                # )
                shutil.copyfile(
                    join_path(libcrux_path, file),
                    join_path(include_dst_path, os.path.basename(file)),
                )
        # Internal and intrinsics header
        copy_dir("internal", dst="include")
        intrinsics_file = "libcrux_intrinsics_avx2.h"
        shutil.copyfile(
            join_path(libcrux_path, "intrinsics", intrinsics_file),
            join_path(include_dst_path, "intrinsics", intrinsics_file),
        )

        # Source files
        for file in os.listdir(libcrux_path):
            if file.endswith(".c"):
                # print(
                #     f"Copy {join_path(libcrux_path, file)} to ",
                #     join_path(include_dst_path, os.path.basename(file)),
                # )
                shutil.copyfile(
                    join_path(libcrux_path, file),
                    join_path(src_dst_path, os.path.basename(file)),
                )

        # if platform.system() == "Windows":
        #     # On Windows we use MSVC etc. by default.
        #     # There's no multi config here. The type needs to be set when configuring.
        #     cmake_args = []
        #     if args.release:
        #         cmake_args.append("-DCMAKE_BUILD_TYPE=Release")
        #     shell(["cmake", "-B", "build"] + cmake_args)
        # else:
        #     # By default we use ninja with a multi config and set the build type
        #     # during the build.
        #     cmake_build_args = []
        #     if args.release:
        #         cmake_build_args.append("--config Release")
        #     shell(["cmake", "-B", "build", "-GNinja Multi-Config"])
        # shell(["cmake", "--build", "build"] + cmake_build_args)
        return None


def parse_arguments():
    parser = argparse.ArgumentParser(description="Libcrux helper.")
    subparsers = parser.add_subparsers()

    update_parser = subparsers.add_parser(
        "update",
        help="Update the libcrux code from upstream.",
    )
    update_parser.add_argument(
        "update",
        nargs="*",
        action=updateAction,
        help="Either a path or a revision must be provided.",
    )
    update_parser.add_argument("--libcrux", help="The libcrux path")
    update_parser.add_argument("--rev", help="The libcrux git revision")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return parser.parse_args()


def main():
    # # Don't print unnecessary Python stack traces.
    # sys.tracebacklimit = 0
    parse_arguments()


if __name__ == "__main__":
    main()
