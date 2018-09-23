"""Limited implementation of Aqara Gateway"""
import json
import logging
import asyncio
import random
import string
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

_LOGGER = logging.getLogger(__name__)


class DiscoveryProtocol(asyncio.DatagramProtocol):
    """Aqara Gateway discovery requests listener (port 4321)"""

    def __init__(self, server):
        self.server = server

    def connection_made(self, transport):
        _LOGGER.info('Discovery %s connected', self.server['ip'])
        self.transport = transport

    def datagram_received(self, data, addr):
        _LOGGER.info('Discovery %s << %s %s', self.server['ip'], data, addr)
        req = json.loads(data.decode())
        # real gateway replies with 'iam' even if client will send an empty request
        if req['cmd'] != 'whois':
            _LOGGER.error('Waited for "whois", got "%s"', req['cmd'])
        res = json.dumps({
            "cmd": "iam",
            "ip": self.server['ip'],
            "port": "9898",
            "model": "gateway",
            "sid": self.server['sid'],
        })
        _LOGGER.info('Discovery %s >> %s %s',
                     self.server['ip'], res.encode(), addr)
        self.transport.sendto(res.encode(), addr)

    def stop(self):
        self.transport.close()


class MainProtocol(asyncio.DatagramProtocol):
    """Aqara Gateway main requests listener (port 9898)"""

    def __init__(self, server):
        self.server = server

    def connection_made(self, transport):
        _LOGGER.info('Main %s connected', self.server['ip'])
        self.transport = transport
        self._gen_key()

    def datagram_received(self, data, addr):
        _LOGGER.info('Main %s << %s %s', self.server['ip'], data, addr)
        req = json.loads(data.decode())
        if req['cmd'] == 'get_id_list':
            res = self._on_get_id_list()
        elif req['cmd'] == 'read':
            res = self._on_read(req)
        elif req['cmd'] == 'write':
            res = self._on_write(req)
        else:
            _LOGGER.error('Main %s got unsupported cmd "%s"', self.server['ip'], req['cmd'])
            return {
                'cmd': 'server_ack',
                'sid': self.server['sid'],
                'data': json.dumps({'error': 'Unsupported cmd'}),
            }

        self.transport.sendto(json.dumps(res).encode(), addr)
        _LOGGER.info('Main %s >> %s %s', self.server['ip'], res, addr)

    def stop(self):
        self.transport.close()

    def _gen_key(self):
        self.token = ''.join(random.choice(
            string.ascii_letters + string.digits) for _ in range(16))
        # https://aqara.gitbooks.io/lumi-gateway-lan-communication-api/content/chapter1.html#2-encryption-mechanism
        init_vector = bytes(bytearray.fromhex(
            '17996d093d28ddb3ba695a2e6f58562e'))
        encryptor = Cipher(algorithms.AES(self.server['key'].encode()),
                           modes.CBC(init_vector),
                           backend=default_backend()).encryptor()
        ciphertext = encryptor.update(
            self.token.encode()) + encryptor.finalize()
        self.key = ''.join('{:02x}'.format(x) for x in ciphertext)

    def _on_get_id_list(self):
        devices = list(self.server['devices'].keys())
        devices.remove(self.server['sid'])
        return {
            'cmd': 'get_id_list_ack',
            'sid': self.server['sid'],
            'token': self.token,
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
        if req['data']['key'] != self.key:
            return {
                'cmd': 'write_ack',
                'sid': device['sid'],
                'data': json.dumps({'error': 'Invalid key'}),
            }

        return {
            'cmd': 'write_ack',
            'model': device['model'],
            'sid': device['sid'],
            'short_id': device['short_id'],
            'data': json.dumps(device['data']),
        }


class AqaraGateway:
    """Emulates Aqara Gateway"""

    def __init__(self, config, event_loop):
        sock = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('224.0.0.50', 4321))
        mreq = socket.inet_aton('224.0.0.50') + socket.inet_aton(config['ip'])
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        discovery_protocol = DiscoveryProtocol(config)
        task = event_loop.create_datagram_endpoint(lambda: discovery_protocol,
                                                   sock=sock)
        asyncio.ensure_future(task, loop=event_loop)
        main_protocol = MainProtocol(config)
        task = event_loop.create_datagram_endpoint(lambda: main_protocol,
                                                   local_addr=(config['ip'], 9898))
        asyncio.ensure_future(task, loop=event_loop)
        self.discovery_protocol = discovery_protocol
        self.main_protocol = main_protocol

    def stop(self):
        self.discovery_protocol.stop()
        self.main_protocol.stop()
