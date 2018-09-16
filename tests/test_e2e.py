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


async def on_server_data(protocol, res, addr):
    if res['sid']=='2':
        await asyncio.sleep(1)
    protocol.transport.sendto(json.dumps(res).encode(), addr)
    _LOGGER.info('Server %s sent %s', protocol.server['ip'], res)
    # protocol.transport.close()

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
    'on_server_data': on_server_data,
}

server2 = {
    'ip': '10.0.0.3',
    'sid': '3', 
    'key': 'c6c36albocvr97fl', 
    'devices': {
        '3': dict({'sid': '3', 'short_id': 0}, **gateway),
        '4': dict({'sid': '4', 'short_id': 40}, **plug),
    },
    'on_server_data': on_server_data,
}

@pytest.mark.asyncio
async def test_main(event_loop, caplog, server_factory, client_factory):
    caplog.set_level(logging.DEBUG)
    pool = ThreadPoolExecutor(max_workers=multiprocessing.cpu_count())
    server_factory(server1)
    server_factory(server2)
    client = client_factory('10.0.0.1', [server1, server2])
    await event_loop.run_in_executor(pool, client.discover_gateways)
    for _ in range(3):
        task1 = event_loop.run_in_executor(pool,
            client.gateways['10.0.0.2'].get_from_hub, '2')
        task2 = event_loop.run_in_executor(pool,
            lambda: client.gateways['10.0.0.3'].write_to_hub('4', status='on'))
        res = await asyncio.gather(task1, task2)
        assert res[0]
        assert res[1]

# #1 from config (+1 device), #1 new (+2 devices), #1 read request, #2 write request 
# #1 new (+1 device), #2 new (+1 device), #1 read request (slow response), #2 write request, #1 should not get write_ack from foreign gateway
# 