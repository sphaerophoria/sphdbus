#!/usr/bin/env bash

set -ex
exit 0

zig fmt build.zig src --check
zig build
./zig-out/bin/dbus_tests

