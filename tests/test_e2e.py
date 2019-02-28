"""End-to-End tests"""
import asyncio
import json
import socket
import logging
import multiprocessing
import struct
import pytest
from concurrent.futures import ThreadPoolExecutor

_LOGGER = logging.getLogger(__name__)

dev_gateway = {
    'model': 'gateway',
    'data': {
        "rgb": 0,
        "illumination": 306,
        "proto_version": '1.1.2',
    }
}

dev_plug = {
    'model': 'plug',
    'data': {
        "voltage": 3600,
        "status": "off",
        "inuse": "0",
        "power_consumed": "12345",
        "load_power": "0.00"
    }
}

dev_magnet = {
    'model': 'magnet',
    'data': {
        "voltage": 3035,
        "status": "close",
    }
}

gateway1 = {
    'ip': '10.0.0.2',
    'sid': '1',
    'key': 'a6c567lbkcmr47fp',
    'devices': {
        '1': dict({'sid': '1', 'short_id': 0}, **dev_gateway),
        '2': dict({'sid': '2', 'short_id': 20}, **dev_magnet),
    },
}

gateway2 = {
    'ip': '10.0.0.3',
    'sid': '3',
    'key': 'c6c36albocvr97fl',
    'devices': {
        '3': dict({'sid': '3', 'short_id': 0}, **dev_gateway),
        '4': dict({'sid': '4', 'short_id': 40}, **dev_plug),
    },
}


@pytest.yield_fixture(autouse=True)
def debug_log(caplog):
    """Asserts logs are lower than warning"""
    caplog.set_level(logging.DEBUG)
    yield
    for record in caplog.get_records('call'):
        assert record.levelno < logging.WARNING


@pytest.fixture(autouse=True)
def gateways(gateway_factory):
    """Automatically creates 2 gateways for each test"""
    gateway_factory(gateway1)
    gateway_factory(gateway2)


@pytest.fixture
def pool():
    """Returns thread pool for sync calls"""
    return ThreadPoolExecutor(max_workers=multiprocessing.cpu_count())


@pytest.mark.asyncio
async def test_simple(event_loop, pool, client_factory):
    """2 gateways discovery -> read gateway #1 -> write gateway #2"""
    client = client_factory('10.0.0.1', [gateway1, gateway2])
    await event_loop.run_in_executor(pool, client.discover_gateways)
    ok = await event_loop.run_in_executor(pool, client.gateways[gateway1['ip']].get_from_hub, '2')
    assert ok
    ok = await event_loop.run_in_executor(pool, lambda: client.gateways[gateway2['ip']].write_to_hub('4', status='on'))
    assert ok


@pytest.mark.asyncio
async def test_race(event_loop, pool, client_factory):
    """2 gateways discovery -> 100 x (read gateway #1 + write gateway #2)
    https://github.com/Danielhiversen/PyXiaomiGateway/issues/45
    """
    client = client_factory('10.0.0.1', [gateway1, gateway2])
    await event_loop.run_in_executor(pool, client.discover_gateways)
    for i in range(100):
        task1 = event_loop.run_in_executor(pool, client.gateways[gateway1['ip']].get_from_hub, '2')
        task2 = event_loop.run_in_executor(pool, lambda: client.gateways[gateway2['ip']].write_to_hub('4', status='on'))
        res = await asyncio.gather(task1, task2)
        assert res[0], "failed on get_from_hub in %i lap" % i
        assert res[1], "failed on write_to_hub in %i lap" % i
