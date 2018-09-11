import asyncio
import json
import socket
import logging
import multiprocessing
import struct
from concurrent.futures import ThreadPoolExecutor
from xiaomi_gateway import XiaomiGatewayDiscovery

_LOGGER = logging.getLogger(__name__)

class DiscoveryProtocol(asyncio.DatagramProtocol):
    def __init__(self, server):
        super().__init__()
        self.server = server

    def connection_made(self, transport):
        _LOGGER.info('Discovery connected %s', self.server['ip'])
        self.transport = transport
    def datagram_received(self, data, addr):
        _LOGGER.info('Discovery %s received: %s %s', self.server['ip'], data, addr)
        req = json.loads(data.decode())
        res = json.dumps({
            "cmd": "iam",
            "ip": self.server['ip'],
            "port": "9898",
            "model": "gateway",
            "sid": self.server['sid'],
        })
        _LOGGER.info('Discovery %s sent: %s', self.server['ip'], res.encode())
        self.transport.sendto(res.encode(), addr)
        # self.transport.close()

class ServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, server):
        super().__init__()
        self.server = server

    def connection_made(self, transport):
        _LOGGER.info('Server %s connected', self.server['ip'])
        self.transport = transport
    def datagram_received(self, data, addr):
        _LOGGER.info('Server %s received %s %s', self.server['ip'], data, addr)
        req = json.loads(data.decode())
        if req['cmd']=='get_id_list':
            res = self._on_get_id_list()
        elif req['cmd']=='read':
            res = self._on_read(req)
        elif req['cmd']=='write':
            res = self._on_write(req)
        asyncio.ensure_future(self.server['on_server_data'](self, res, addr))
    def _on_get_id_list(self):
        devices = list(self.server['devices'].keys())
        devices.remove(self.server['sid'])
        return {
            'cmd': 'get_id_list_ack',
            'sid': self.server['sid'],
            'token': 'dsiT9MDnNQ8E5fQ6',
            'data': json.dumps(devices),
        }
    def _on_read(self, req):
        device = self.server['devices'][req['sid']]
        return {
            'cmd': 'read_ack', 
            'model': device['model'], 
            'sid': device['sid'], 
            'short_id': device['short_id'], 
            'data': json.dumps(device['data']),
        }
    def _on_write(self, req):
        device = self.server['devices'][req['sid']]
        device['data']['status'] = req['data']['status']
        return {
            'cmd': 'write_ack', 
            'model': device['model'], 
            'sid': device['sid'], 
            'short_id': device['short_id'], 
            'data': json.dumps(device['data']),
        }

def start_server(loop, server):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('224.0.0.50', 4321))
    mreq = socket.inet_aton('224.0.0.50') + socket.inet_aton(server['ip'])
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    t = loop.create_datagram_endpoint(lambda: DiscoveryProtocol(server),
                                      sock=sock)
    loop.run_until_complete(t)
    t = loop.create_datagram_endpoint(lambda: ServerProtocol(server),
                                      local_addr=(server['ip'], 9898))
    loop.run_until_complete(t)

def callback():
    print('callback called')

async def start_client(loop, pool, ip, gateways):
    xiaomi = XiaomiGatewayDiscovery(callback, [{
        'key': gateways[0]['key'],
        'sid': gateways[0]['sid'],
    }, {
        'key': gateways[1]['key'],
        'sid': gateways[1]['sid'],
    }], ip)
    await loop.run_in_executor(pool, xiaomi.discover_gateways)
    for i in range(3):
        task1 = loop.run_in_executor(pool,
            xiaomi.gateways['10.0.0.2'].get_from_hub, '2')
        task2 = loop.run_in_executor(pool,
            lambda: xiaomi.gateways['10.0.0.3'].write_to_hub('4', status='on'))
        await asyncio.gather(task1, task2)

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

FORMAT = '%(asctime)-15s %(message)s'
logging.basicConfig(level=logging.DEBUG, format=FORMAT)
pool = ThreadPoolExecutor(max_workers=multiprocessing.cpu_count())
loop = asyncio.get_event_loop()
start_server(loop, server1)
start_server(loop, server2)
loop.run_until_complete(start_client(loop, pool, '10.0.0.1',
    [server1, server2]))

# #1 from config (+1 device), #1 new (+2 devices), #1 read request, #2 write request 
# #1 new (+1 device), #2 new (+1 device), #1 read request (slow response), #2 write request, #1 should not get write_ack from foreign gateway
# 