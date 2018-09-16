"""Set up some common test helper things."""
import pytest
import socket
import asyncio
from tests.gateway import DiscoveryProtocol, ServerProtocol
from xiaomi_gateway import XiaomiGatewayDiscovery

@pytest.fixture
def server_factory(event_loop):
    def start_server(server):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('224.0.0.50', 4321))
        mreq = socket.inet_aton('224.0.0.50') + socket.inet_aton(server['ip'])
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        t = event_loop.create_datagram_endpoint(lambda: DiscoveryProtocol(server),
                                        sock=sock)
        asyncio.ensure_future(t, loop=event_loop)
        t = event_loop.create_datagram_endpoint(lambda: ServerProtocol(server),
                                        local_addr=(server['ip'], 9898))
        asyncio.ensure_future(t, loop=event_loop)
    
    return start_server

@pytest.fixture
def client_factory():
    def start_client(ip, gateways):
        return XiaomiGatewayDiscovery(lambda: None, [{
            'key': gateways[0]['key'],
            'sid': gateways[0]['sid'],
        }, {
            'key': gateways[1]['key'],
            'sid': gateways[1]['sid'],
        }], ip)
    return start_client