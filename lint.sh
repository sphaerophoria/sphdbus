#!/usr/bin/env bash

set -ex

zig fmt build.zig src --check
zig build
./zig-out/bin/dbus_tests

