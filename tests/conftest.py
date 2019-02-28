"""Set up some common test helper things."""
import pytest
import socket
import asyncio
from tests.gateway import AqaraGateway
from xiaomi_gateway import XiaomiGatewayDiscovery


@pytest.yield_fixture
def gateway_factory(event_loop):
    """Factory that creates new gateways"""
    gateways = []

    def start_gateway(config):
        gateways.append(AqaraGateway(config, event_loop))

    yield start_gateway
    [gateway.stop() for gateway in gateways]


@pytest.yield_fixture
def client_factory():
    """Factory that creates new gateway clients"""
    clients = []

    def start_client(ip, gateways):
        config = []
        [config.append({'key': g['key'], 'sid': g['sid']}) for g in gateways]
        client = XiaomiGatewayDiscovery(lambda: None, config, ip)
        clients.append(client)
        return client

    yield start_client
    [client.stop_listen() for client in clients]
