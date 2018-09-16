import asyncio
import json
import socket
import logging
import multiprocessing
import struct
import pytest
from concurrent.futures import ThreadPoolExecutor
from xiaomi_gateway import XiaomiGatewayDiscovery

_LOGGER = logging.getLogger(__name__)


async def on_server_data_default(protocol, res, addr):
    protocol.transport.sendto(json.dumps(res).encode(), addr)
    _LOGGER.info('Server %s sent %s', protocol.server['ip'], res)

gateway = {
    'model': 'gateway',
    'data': {
        "rgb": 0,
        "illumination": 306,
        "proto_version": '1.1.2',
    }
}

plug = {
    'model': 'plug',
    'data': {
        "voltage": 3600,
        "status": "off",
        "inuse": "0",
        "power_consumed": "38344",
        "load_power": "0.00"
    }
}

magnet = {
    'model': 'magnet',
    'data': {
        "voltage": 3035,
        "status": "close",
    }
}

server1 = {
    'ip': '10.0.0.2',
    'sid': '1',
    'key': 'a6c567lbkcmr47fp',
    'devices': {
        '1': dict({'sid': '1', 'short_id': 0}, **gateway),
        '2': dict({'sid': '2', 'short_id': 20}, **magnet),
    },
    'on_server_data': on_server_data_default,
}

server2 = {
    'ip': '10.0.0.3',
    'sid': '3', 
    'key': 'c6c36albocvr97fl', 
    'devices': {
        '3': dict({'sid': '3', 'short_id': 0}, **gateway),
        '4': dict({'sid': '4', 'short_id': 40}, **plug),
    },
    'on_server_data': on_server_data_default,
}

@pytest.yield_fixture(autouse=True)
def debug_log(caplog):
    caplog.set_level(logging.DEBUG)
    yield
    for record in caplog.get_records('call'):
        assert record.levelno<logging.WARNING

@pytest.fixture(autouse=True)
def servers(server_factory):
    server_factory(server1)
    server_factory(server2)

@pytest.fixture
def pool():
    return ThreadPoolExecutor(max_workers=multiprocessing.cpu_count())

@pytest.mark.asyncio
async def test_simple(event_loop, pool, client_factory):
    client = client_factory('10.0.0.1', [server1, server2])
    await event_loop.run_in_executor(pool, client.discover_gateways)
    ok = await event_loop.run_in_executor(pool,
        client.gateways['10.0.0.2'].get_from_hub, '2')
    assert ok
    ok = await event_loop.run_in_executor(pool,
        lambda: client.gateways['10.0.0.3'].write_to_hub('4', status='on'))
    assert ok

@pytest.mark.asyncio
async def test_race(event_loop, pool, client_factory):
    async def on_server_data(protocol, res, addr):
        if res['sid']=='2':
            await asyncio.sleep(1)
        protocol.transport.sendto(json.dumps(res).encode(), addr)
        _LOGGER.info('Server %s sent %s', protocol.server['ip'], res)
    server1['on_server_data'] = on_server_data
    client = client_factory('10.0.0.1', [server1, server2])
    await event_loop.run_in_executor(pool, client.discover_gateways)
    for i in range(3):
        task1 = event_loop.run_in_executor(pool,
            client.gateways['10.0.0.2'].get_from_hub, '2')
        task2 = event_loop.run_in_executor(pool,
            lambda: client.gateways['10.0.0.3'].write_to_hub('4', status='on'))
        res = await asyncio.gather(task1, task2)
        assert res[0], "failed on get_from_hub in %i lap" % i
        assert res[1], "failed on write_to_hub in %i lap" % i
