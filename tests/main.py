import asyncio
import json
import socket
import logging
import multiprocessing
import struct
from concurrent.futures import ThreadPoolExecutor
from xiaomi_gateway import XiaomiGatewayDiscovery

class DiscoveryProtocol(asyncio.DatagramProtocol):
    def __init__(self, server):
        super().__init__()
        self.server = server

    def connection_made(self, transport):
        print('Discovery connected', self.server['ip'])
        self.transport = transport
    def datagram_received(self, data, addr):
        req = json.loads(data.decode())
        print('Discovery', self.server['ip'], 'received:', req, addr)
        res = json.dumps({
            "cmd": "iam",
            "ip": self.server['ip'],
            "port": "9898",
            "model": "gateway",
            "sid": self.server['sid'],
        })
        print('Discovery', self.server['ip'], 'sent:', res)
        self.transport.sendto(res.encode(), addr)
        # self.transport.close()

class ServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, server):
        super().__init__()
        self.server = server

    def connection_made(self, transport):
        print('Server connected')
        self.transport = transport
    def datagram_received(self, data, addr):
        print('Server', self.server['ip'], 'received', data, 'from', addr)
        req = json.loads(data.decode())
        if req['cmd']=='get_id_list':
            devices = list(self.server['devices'].keys())
            devices.remove(self.server['sid'])
            res = {
                'cmd': 'get_id_list_ack',
                'sid': self.server['sid'],
                'token': 'dsiT9MDnNQ8E5fQ6',
                'data': json.dumps(devices),
            }
        elif req['cmd']=='read':
            device = self.server['devices'][req['sid']]
            res = {
                'cmd': 'read_ack', 
                'model': device['model'], 
                'sid': device['sid'], 
                'short_id': device['short_id'], 
                'data': json.dumps(device['data']),
            }
        print('Server', self.server['ip'], 'sent', res)
        self.transport.sendto(json.dumps(res).encode(), addr)
        # self.transport.close()

class ClientProtocol:
    def __init__(self):
        self.transport = None
        self.res_count = 0

    def connection_made(self, transport):
        print('Client connected')
        self.transport = transport
        data = '{"cmd":"whois"}'
        print('Client send:', data)
        self.transport.sendto(data.encode(), ('224.0.0.51', 4321))

    def connection_lost(self, exc):
        loop = asyncio.get_event_loop()
        loop.stop()

    def datagram_received(self, data, addr):
        print("Client received:", data.decode(), addr)
        self.res_count = self.res_count+1
        if self.res_count==2:
            self.transport.close()

def start_server(loop, ip):
    server = {
        'ip': ip, 
        'sid': '1', 
        'devices': {
            '1': {
                'model': 'gateway',
                'sid': '1',
                'short_id': 0,
                'data': {
                    "rgb": 0,
                    "illumination": 306,
                    "proto_version": '1.1.2',
                }
            },
            '2': {
                'model': 'plug',
                'sid': '2',
                'short_id': 458,
                'data': {
                    "voltage":3600,
                    "status":"off",
                    "inuse":"0",
                    "power_consumed":"38344",
                    "load_power":"0.00"
                }
            }
        }
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('224.0.0.50', 4321))
    mreq = socket.inet_aton('224.0.0.50') + socket.inet_aton(ip)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    t = loop.create_datagram_endpoint(lambda: DiscoveryProtocol(server),
                                      sock=sock)
    loop.run_until_complete(t)
    t = loop.create_datagram_endpoint(lambda: ServerProtocol(server),
                                      local_addr=(ip, 9898))
    loop.run_until_complete(t)

def callback():
    print('callback called')

async def start_client(loop, ip, pool):
    xiaomi = XiaomiGatewayDiscovery(callback, [], ip)
    await loop.run_in_executor(pool, xiaomi.discover_gateways)

logging.basicConfig(level=logging.DEBUG)
pool = ThreadPoolExecutor(max_workers=multiprocessing.cpu_count())
loop = asyncio.get_event_loop()
start_server(loop, '10.0.0.2')
start_server(loop, '10.0.0.3')
loop.run_until_complete(start_client(loop, '10.0.0.1', pool))
