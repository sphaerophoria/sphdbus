#!/usr/bin/env python3

import subprocess
import sys
import asyncio

from dbus_next.aio import MessageBus
from dbus_next.constants import BusType

BUS_NAME = "dev.sphaerophoria.TestService"
OBJECT_PATH = "/dev/sphaerophoria/TestService"
INTERFACE = "dev.sphaerophoria.TestService"
SERVICE_BIN = "zig-out/bin/service_example"
SIGNAL_INTERVAL_MS = 150


async def create_proxy(bus):
    for attempt in range(20):
        try:
            introspection = await bus.introspect(BUS_NAME, OBJECT_PATH)
            return bus.get_proxy_object(BUS_NAME, OBJECT_PATH, introspection).get_interface(INTERFACE)
        except Exception:
            await asyncio.sleep(0.5)
    raise RuntimeError("Service did not appear on bus within 10 seconds")


async def test_hello(interface):
    result = await interface.call_hello("World")
    assert result == "Hello World"


async def test_goodbye(interface):
    result = await interface.call_goodbye("Developer")
    assert result == "Goodbye Developer"


async def test_call_me(interface):
    result = await interface.call_call_me()
    assert result == "maybe"


async def test_get_structure(interface):
    result = await interface.call_get_structure()
    expected_int = 0xcafef00d
    assert result[0] == expected_int
    assert abs(result[1] - 1.234) < 1e-6
    assert result[2] == ord('d')


async def test_get_uint_array(interface):
    result = await interface.call_get_uint_array()
    expected = list(range(100))
    actual = list(result)
    assert actual == expected


async def test_get_struct_array(interface):
    result = await interface.call_get_struct_array()
    actual = list(result)
    assert len(actual) == 100
    for i in range(100):
        assert list(actual[i]) == ["hello", i]


async def test_get_nested_struct_array(interface):
    result = await interface.call_get_nested_struct_array()
    actual = list(result)
    assert len(actual) == 2
    for j in range(2):
        inner = list(actual[j])
        assert len(inner) == 100
        for i in range(100):
            expected_val = j * 100 + i
            assert list(inner[i]) == ["hello", expected_val]


async def test_method_not_exist(interface):
    try:
        await interface.call_non_existent_method()
        assert False
    except Exception:
        pass


async def run_tests(proxy):
    signal_event = asyncio.Event()

    def on_update(message):
        signal_event.set()

    proxy.on_update(on_update)

    try:
        signal_task = asyncio.create_task(signal_event.wait())

        await test_hello(proxy)
        await test_goodbye(proxy)
        await test_call_me(proxy)
        await test_get_structure(proxy)
        await test_get_uint_array(proxy)
        await test_get_struct_array(proxy)
        await test_get_nested_struct_array(proxy)

        await signal_task

        await test_method_not_exist(proxy)
    finally:
        proxy.off_update(on_update)


async def main():
    service_bin = SERVICE_BIN

    service = subprocess.Popen([service_bin, str(SIGNAL_INTERVAL_MS)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        bus = await MessageBus(bus_type=BusType.SESSION).connect()
        proxy = await create_proxy(bus)
        await run_tests(proxy)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    finally:
        service.terminate()
        try:
            service.wait(timeout=5)
        except Exception:
            service.kill()
            service.wait()


if __name__ == "__main__":
    asyncio.run(main())

