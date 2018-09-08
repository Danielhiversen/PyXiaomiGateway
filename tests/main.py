import asyncio
import json
import socket
import logging
import multiprocessing
import struct
from concurrent.futures import ThreadPoolExecutor
# from xiaomi_gateway import XiaomiGatewayDiscovery

class DiscoveryProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        super().__init__()
    def connection_made(self, transport):
        print('Discovery connected')
        self.transport = transport
    def datagram_received(self, data, addr):
        req = json.loads(data.decode())
        print('Discovery received:', req)
        res = json.dumps({
            "cmd": "iam",
            "ip": "127.0.0.1",
            "port": "9898",
            "model": "gateway",
            "sid": "1232",
        })
        print('Discovery sent:', res)
        self.transport.sendto(res.encode(), addr)
        self.transport.close()

class ServerProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        super().__init__()
    def connection_made(self, transport):
        print('Server connected')
        self.transport = transport
    def datagram_received(self, data, addr):
        print('Server received:', data, 'from:', addr)
        print('Server sent:', data, 'to:', addr)
        self.transport.sendto(data, addr)
        self.transport.close()

class ClientProtocol:
    def __init__(self):
        self.transport = None

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
        print("Client received:", data.decode())
        self.transport.close()

def start_server(loop):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('224.0.0.51', 4321))
    mreq = struct.pack("4sl", socket.inet_aton('224.0.0.51'), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    t = loop.create_datagram_endpoint(DiscoveryProtocol,
                                      sock=sock)
    loop.run_until_complete(t)
    t = loop.create_datagram_endpoint(ServerProtocol,
                                      local_addr=('0.0.0.0', 9898))
    loop.run_until_complete(t)

def callback():
    print('callback called')

def start_client(loop, pool):
    t = loop.create_datagram_endpoint(ClientProtocol,
        local_addr=('0.0.0.0', 0))
    loop.run_until_complete(t)
    # xiaomi = XiaomiGatewayDiscovery(callback, [], 'any')
    # loop.run_in_executor(pool, xiaomi.discover_gateways)

logging.basicConfig(level=logging.DEBUG)
pool = ThreadPoolExecutor(max_workers=multiprocessing.cpu_count())
loop = asyncio.get_event_loop()
start_server(loop)
start_client(loop, pool)
loop.run_forever()
