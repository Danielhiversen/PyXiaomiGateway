"""Set up some common test helper things."""
import pytest
import socket
import asyncio
from tests.gateway import DiscoveryProtocol, ServerProtocol
from xiaomi_gateway import XiaomiGatewayDiscovery

@pytest.yield_fixture
def server_factory(event_loop):
    protocols = []
    def start_server(server):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('224.0.0.50', 4321))
        mreq = socket.inet_aton('224.0.0.50') + socket.inet_aton(server['ip'])
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        discovery_protocol = DiscoveryProtocol(server)
        t = event_loop.create_datagram_endpoint(lambda: discovery_protocol,
                                                sock=sock)
        asyncio.ensure_future(t, loop=event_loop)
        server_protocol = ServerProtocol(server)
        t = event_loop.create_datagram_endpoint(lambda: server_protocol,
                                        local_addr=(server['ip'], 9898))
        asyncio.ensure_future(t, loop=event_loop)
        protocols.append(discovery_protocol)
        protocols.append(server_protocol)
    
    yield start_server
    [protocol.stop() for protocol in protocols]

@pytest.yield_fixture
def client_factory():
    clients = []
    def start_client(ip, gateways):
        client = XiaomiGatewayDiscovery(lambda: None, [{
            'key': gateways[0]['key'],
            'sid': gateways[0]['sid'],
        }, {
            'key': gateways[1]['key'],
            'sid': gateways[1]['sid'],
        }], ip)
        clients.append(client)
        return client

    yield start_client
    [client.stop_listen() for client in clients]
