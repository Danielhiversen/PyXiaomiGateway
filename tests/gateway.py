import json
import logging
import asyncio

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
        res = json.dumps({
            "cmd": "iam",
            "ip": self.server['ip'],
            "port": "9898",
            "model": "gateway",
            "sid": self.server['sid'],
        })
        _LOGGER.info('Discovery %s sent: %s', self.server['ip'], res.encode())
        self.transport.sendto(res.encode(), addr)
    def stop(self):
        self.transport.close()


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
        self.transport.sendto(json.dumps(res).encode(), addr)
        _LOGGER.info('Server %s sent %s', self.server['ip'], res)
    def stop(self):
        self.transport.close()
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
