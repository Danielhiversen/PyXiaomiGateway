"""Library to handle connection with Xiaomi Gateway"""
import asyncio
import socket
import json
import logging
import platform
import struct
from collections import defaultdict
from threading import Thread
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

_LOGGER = logging.getLogger(__name__)

DEFAULT_DISCOVERY_RETRIES = 4

GATEWAY_MODELS = ['gateway', 'gateway.v3', 'acpartner.v3']
SOCKET_BUFSIZE = 4096
MULTICAST_PORT = 9898
MULTICAST_ADDRESS = '224.0.0.50'


def create_mcast_socket(interface, port, bind_interface=True, blocking=True):
    """Create and bind a socket for communication."""
    # Host IP adress is recommended as interface.
    if interface == "any":
        ip32bit = socket.INADDR_ANY
        bind_interface = False
        mreq = struct.pack("=4sl", socket.inet_aton(MULTICAST_ADDRESS), ip32bit)
    else:
        ip32bit = socket.inet_aton(interface)
        mreq = socket.inet_aton(MULTICAST_ADDRESS) + ip32bit

    udp_socket = socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP
    )
    udp_socket.setblocking(blocking)

    # Required for receiving multicast
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, ip32bit)
    except:
        _LOGGER.error(
            "Error creating multicast socket using IPPROTO_IP, trying SOL_IP"
        )
        udp_socket.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, ip32bit)

    try:
        udp_socket.setsockopt(
            socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq,
        )
    except:
        _LOGGER.error(
            "Error adding multicast socket membership using IPPROTO_IP, trying SOL_IP"
        )
        udp_socket.setsockopt(
            socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, mreq,
        )

    udp_socket.bind((interface if bind_interface else "", port))

    return udp_socket


class AsyncXiaomiGatewayMulticast:
    """Async Multicast UDP communication class for a XiaomiGateway."""

    def __init__(self, interface="any", bind_interface=True):
        self._listen_couroutine = None
        self._interface = interface
        self._bind_interface = bind_interface

        self._registered_callbacks = {}

    def _create_udp_listener(self):
        """Create the UDP multicast socket and protocol."""
        udp_socket = create_mcast_socket(
            self._interface, MULTICAST_PORT, bind_interface=self._bind_interface, blocking=False
        )

        loop = asyncio.get_event_loop()

        return loop.create_datagram_endpoint(
            lambda: self.MulticastListenerProtocol(loop, udp_socket, self),
            sock=udp_socket,
        )

    @property
    def interface(self):
        """Return the used interface."""
        return self._interface

    @property
    def bind_interface(self):
        """Return if the interface is bound."""
        return self._bind_interface

    def register_gateway(self, ip, callback):
        """Register a Gateway to this Multicast listener."""
        if ip in self._registered_callbacks:
            _LOGGER.error(
                "A callback for ip '%s' was already registed, overwriting previous callback",
                ip,
            )
        self._registered_callbacks[ip] = callback

    def unregister_gateway(self, ip):
        """Unregister a Gateway from this Multicast listener."""
        if ip in self._registered_callbacks:
            self._registered_callbacks.pop(ip)

    async def start_listen(self):
        """Start listening."""
        if self._listen_couroutine is not None:
            _LOGGER.error(
                "Multicast listener already started, not starting another one."
            )
            return

        listen_task = self._create_udp_listener()
        _, self._listen_couroutine = await listen_task

    def stop_listen(self):
        """Stop listening."""
        if self._listen_couroutine is None:
            return

        self._listen_couroutine.close()
        self._listen_couroutine = None

    class MulticastListenerProtocol:
        """Handle received multicast messages."""

        def __init__(self, loop, udp_socket, parent):
            """Initialize the class."""
            self.transport = None
            self._loop = loop
            self._sock = udp_socket
            self._parent = parent
            self._connected = False

        def connection_made(self, transport):
            """Set the transport."""
            self.transport = transport
            self._connected = True
            _LOGGER.info("XiaomiMulticast listener started")

        def connection_lost(self, exc):
            """Handle connection lost."""
            if self._connected:
                _LOGGER.error(
                    "Connection unexpectedly lost in XiaomiMulticast listener: %s", exc
                )

        def datagram_received(self, data, addr):
            """Handle received messages."""
            try:
                (ip_add, _) = addr
                message = json.loads(data.decode("ascii"))

                if ip_add not in self._parent._registered_callbacks:
                    _LOGGER.info("Unknown Xiaomi gateway ip %s", ip_add)
                    return

                callback = self._parent._registered_callbacks[ip_add]
                callback(message)

            except Exception:
                _LOGGER.exception("Cannot process multicast message: '%s'", data)

        def error_received(self, exc):
            """Log UDP errors."""
            _LOGGER.error("UDP error received in XiaomiMulticast listener: %s", exc)

        def close(self):
            """Stop the server."""
            _LOGGER.debug("XiaomiMulticast listener shutting down")
            self._connected = False
            if self.transport:
                self.transport.close()
            try:
                self._loop.remove_writer(self._sock.fileno())
            except NotImplementedError:
                pass
            try:
                self._loop.remove_reader(self._sock.fileno())
            except NotImplementedError:
                pass
            self._sock.close()
            _LOGGER.info("XiaomiMulticast listener stopped")


class XiaomiGatewayDiscovery:
    """PyXiami."""
    # pylint: disable=too-many-instance-attributes
    GATEWAY_DISCOVERY_PORT = 4321

    def __init__(self, interface, device_discovery_retries=DEFAULT_DISCOVERY_RETRIES):

        self.gateways = defaultdict(list)
        self._interface = interface
        self._device_discovery_retries = device_discovery_retries

    # pylint: disable=too-many-branches, too-many-locals, too-many-statements
    def discover_gateways(self):
        """Discover gateways using multicast"""

        _socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _socket.settimeout(5.0)
        if self._interface != 'any':
            _socket.bind((self._interface, 0))

        try:
            _socket.sendto('{"cmd":"whois"}'.encode(),
                           (MULTICAST_ADDRESS, self.GATEWAY_DISCOVERY_PORT))

            while True:
                data, (ip_add, _) = _socket.recvfrom(SOCKET_BUFSIZE)
                if len(data) is None:
                    continue

                if ip_add in self.gateways.keys():
                    continue

                resp = json.loads(data.decode())
                if resp["cmd"] != 'iam':
                    _LOGGER.error("Response does not match return cmd")
                    continue

                if resp["model"] not in GATEWAY_MODELS:
                    _LOGGER.error("Response must be gateway model")
                    continue

                gateway_key = None
                sid = resp["sid"]
                _LOGGER.info('Xiaomi Gateway %s found at IP %s', sid, ip_add)
                self.gateways[ip_add] = XiaomiGateway(
                    ip_add, sid, gateway_key,
                    self._device_discovery_retries, self._interface, resp["port"],
                    resp["proto_version"] if "proto_version" in resp else None)

        except socket.timeout:
            _LOGGER.info("Gateway discovery finished in 5 seconds")
            _socket.close()


# pylint: disable=too-many-instance-attributes
class XiaomiGateway:
    """Xiaomi Gateway Component"""

    # pylint: disable=too-many-arguments
    def __init__(self, ip_adress, sid, key, discovery_retries, interface, port=MULTICAST_PORT, proto=None):

        self.ip_adress = ip_adress
        self.port = int(port)
        self.sid = sid
        self.key = key
        self.devices = defaultdict(list)
        self.callbacks = defaultdict(list)
        self.token = None
        self.connection_error = False
        self.mac_error = False
        self._discovery_retries = discovery_retries
        self._interface = interface

        if proto is None:
            cmd = '{"cmd":"read","sid":"' + sid + '"}'
            resp = self._send_cmd(cmd)
            proto = _get_value(resp, "proto_version") if _validate_data(resp) else None
        self.proto = '1.0' if proto is None else proto

        trycount = 5
        for _ in range(trycount):
            _LOGGER.info('Discovering Xiaomi Devices')
            if self._discover_devices():
                break

    # pylint: disable=too-many-branches
    def _discover_devices(self):

        cmd = '{"cmd" : "get_id_list"}' if int(self.proto[0:1]) == 1 else '{"cmd":"discovery"}'
        resp = self._send_cmd(cmd, "get_id_list_ack") if int(self.proto[0:1]) == 1 \
            else self._send_cmd(cmd, "discovery_rsp")
        if resp is None or "token" not in resp or ("data" not in resp and "dev_list" not in resp):
            return False
        self.token = resp['token']
        sids = []
        if int(self.proto[0:1]) == 1:
            sids = json.loads(resp["data"])
        else:
            for dev in resp["dev_list"]:
                sids.append(dev["sid"])
        sids.append(self.sid)

        _LOGGER.info('Found %s devices', len(sids))

        device_types = {
            'sensor': ['sensor_ht', 'gateway', 'gateway.v3', 'weather',
                       'weather.v1', 'sensor_motion.aq2', 'acpartner.v3', 'vibration'],
            'binary_sensor': ['magnet', 'sensor_magnet', 'sensor_magnet.aq2',
                              'motion', 'sensor_motion', 'sensor_motion.aq2',
                              'switch', 'sensor_switch', 'sensor_switch.aq2', 'sensor_switch.aq3', 'remote.b1acn01',
                              '86sw1', 'sensor_86sw1', 'sensor_86sw1.aq1', 'remote.b186acn01', 'remote.b186acn02',
                              '86sw2', 'sensor_86sw2', 'sensor_86sw2.aq1', 'remote.b286acn01', 'remote.b286acn02',
                              'cube', 'sensor_cube', 'sensor_cube.aqgl01',
                              'smoke', 'sensor_smoke',
                              'natgas', 'sensor_natgas',
                              'sensor_wleak.aq1',
                              'vibration', 'vibration.aq1'],
            'switch': ['plug',
                       'ctrl_neutral1', 'ctrl_neutral1.aq1', 'switch_b1lacn02', 'switch.b1lacn02',
                       'ctrl_neutral2', 'ctrl_neutral2.aq1', 'switch_b2lacn02', 'switch.b2lacn02',
                       'ctrl_ln1', 'ctrl_ln1.aq1', 'switch_b1nacn02', 'switch.b1nacn02',
                       'ctrl_ln2', 'ctrl_ln2.aq1', 'switch_b2nacn02', 'switch.b2nacn02',
                       '86plug', 'ctrl_86plug', 'ctrl_86plug.aq1'],
            'light': ['gateway', 'gateway.v3'],
            'cover': ['curtain', 'curtain.aq2', 'curtain.hagl04'],
            'lock': ['lock.aq1', 'lock.acn02']}

        for sid in sids:
            cmd = '{"cmd":"read","sid":"' + sid + '"}'
            for retry in range(self._discovery_retries):
                _LOGGER.debug("Discovery attempt %d/%d", retry + 1, self._discovery_retries)
                resp = self._send_cmd(cmd, "read_ack") if int(self.proto[0:1]) == 1 else self._send_cmd(cmd, "read_rsp")
                if _validate_data(resp):
                    break
            if not _validate_data(resp):
                _LOGGER.error("Not a valid device. Check the mac adress and update the firmware.")
                self.mac_error = True
                continue

            model = resp["model"]
            supported = False

            for device_type in device_types:
                if model in device_types[device_type]:
                    supported = True
                    xiaomi_device = {
                        "model": model,
                        "proto": self.proto,
                        "sid": resp["sid"].rjust(12, '0'),
                        "short_id": resp["short_id"] if "short_id" in resp else 0,
                        "data": _list2map(_get_value(resp)),
                        "raw_data": resp}
                    self.devices[device_type].append(xiaomi_device)
                    _LOGGER.debug('Registering device %s, %s as: %s', sid, model, device_type)

            if not supported:
                if model:
                    _LOGGER.error(
                        'Unsupported device found! Please create an issue at '
                        'https://github.com/Danielhiversen/PyXiaomiGateway/issues '
                        'and provide the following data: %s', resp)
                else:
                    _LOGGER.error(
                        'The device with sid %s isn\'t supported of the used '
                        'gateway firmware. Please update the gateway firmware if '
                        'possible! This is the only way the issue can be solved.',
                        resp["sid"])

                continue
        return True

    def _send_cmd(self, cmd, rtn_cmd=None):
        try:
            _socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if self._interface != 'any':
                _socket.bind((self._interface, 0))
            _socket.settimeout(10.0)
            _LOGGER.debug("_send_cmd >> %s", cmd.encode())
            _socket.sendto(cmd.encode(), (self.ip_adress, self.port))
            data, _ = _socket.recvfrom(SOCKET_BUFSIZE)
        except socket.timeout:
            _LOGGER.error("Cannot connect to gateway %s", self.sid)
            self.connection_error = True
            return None
        finally:
            _socket.close()
        if data is None:
            _LOGGER.error("No response from gateway %s", self.sid)
            return None
        resp = json.loads(data.decode())
        _LOGGER.debug("_send_cmd resp << %s", resp)
        if rtn_cmd is not None and resp['cmd'] != rtn_cmd:
            _LOGGER.error("Non matching response. Expecting %s, but got %s", rtn_cmd, resp['cmd'])
            return None
        return resp

    def write_to_hub(self, sid, **kwargs):
        """Send data to gateway to turn on / off device"""
        if self.key is None:
            _LOGGER.error('Gateway Key is not provided. Can not send commands to the gateway.')
            return False
        data = {}
        for key in kwargs:
            data[key] = kwargs[key]
        if not self.token:
            _LOGGER.debug('Gateway Token was not obtained yet. Cannot send commands to the gateway.')
            return False

        cmd = dict()
        cmd['cmd'] = 'write'
        cmd['sid'] = sid
        if int(self.proto[0:1]) == 1:
            data['key'] = self._get_key()
            cmd['data'] = data
        else:
            cmd['key'] = self._get_key()
            cmd['params'] = [data]
        resp = self._send_cmd(json.dumps(cmd), "write_ack") if int(self.proto[0:1]) == 1 \
            else self._send_cmd(json.dumps(cmd), "write_rsp")
        _LOGGER.debug("write_ack << %s", resp)
        if _validate_data(resp):
            return True
        if not _validate_keyerror(resp):
            return False

        # If 'invalid key' message we ask for a new token
        resp = self._send_cmd('{"cmd" : "get_id_list"}', "get_id_list_ack") if int(self.proto[0:1]) == 1 \
            else self._send_cmd('{"cmd" : "discovery"}', "discovery_rsp")
        _LOGGER.debug("get_id_list << %s", resp)

        if resp is None or "token" not in resp:
            _LOGGER.error('No new token from gateway. Can not send commands to the gateway.')
            return False
        self.token = resp['token']
        if int(self.proto[0:1]) == 1:
            data['key'] = self._get_key()
            cmd['data'] = data
        else:
            cmd['key'] = self._get_key()
            cmd['params'] = [data]
        resp = self._send_cmd(json.dumps(cmd), "write_ack") if int(self.proto[0:1]) == 1 \
            else self._send_cmd(json.dumps(cmd), "write_rsp")
        _LOGGER.debug("write_ack << %s", resp)
        return _validate_data(resp)

    def get_from_hub(self, sid):
        """Get data from gateway"""
        cmd = '{ "cmd":"read","sid":"' + sid + '"}'
        resp = self._send_cmd(cmd, "read_ack") if int(self.proto[0:1]) == 1 else self._send_cmd(cmd, "read_rsp")
        _LOGGER.debug("read_ack << %s", resp)
        return self.push_data(resp)

    def multicast_callback(self, message):
        """Push data broadcasted from gateway"""          
        cmd = message['cmd']
        if cmd == 'heartbeat' and message['model'] in GATEWAY_MODELS:
            self.token = message['token']
        elif cmd in ('report', 'heartbeat'):
            _LOGGER.debug('MCAST (%s) << %s', cmd, message)
            self.push_data(message)
        else:
            _LOGGER.error('Unknown multicast message: %s', message)

    def push_data(self, data):
        """Push data broadcasted from gateway to device"""
        if not _validate_data(data):
            return False
        jdata = json.loads(data['data']) if int(self.proto[0:1]) == 1 else _list2map(data['params'])
        if jdata is None:
            return False
        sid = data['sid']
        for func in self.callbacks[sid]:
            func(jdata, data)
        return True

    def _get_key(self):
        """Get key using token from gateway"""
        init_vector = bytes(bytearray.fromhex('17996d093d28ddb3ba695a2e6f58562e'))
        encryptor = Cipher(algorithms.AES(self.key.encode()), modes.CBC(init_vector),
                           backend=default_backend()).encryptor()
        ciphertext = encryptor.update(self.token.encode()) + encryptor.finalize()
        if isinstance(ciphertext, str):  # For Python 2 compatibility
            return ''.join('{:02x}'.format(ord(x)) for x in ciphertext)
        return ''.join('{:02x}'.format(x) for x in ciphertext)


def _validate_data(data):
    if data is None or ("data" not in data and "params" not in data):
        _LOGGER.error('No data in response from hub %s', data)
        return False
    if "data" in data and 'error' in json.loads(data['data']):
        _LOGGER.error('Got error element in data %s', data['data'])
        return False
    if "params" in data:
        for param in data['params']:
            if 'error' in param:
                _LOGGER.error('Got error element in data %s', data['params'])
                return False
    return True


def _validate_keyerror(data):
    if data is not None and "data" in data and 'Invalid key' in data['data']:
        return True
    if data is not None and "params" in data:
        for param in data['params']:
            if 'error' in param and 'Invalid key' in param['error']:
                return True
    return False


def _get_value(resp, data_key=None):
    if not _validate_data(resp):
        return None
    data = json.loads(resp["data"]) if "data" in resp else resp["params"]
    if data_key is None:
        return data
    if isinstance(data, list):
        for param in data:
            if data_key in param:
                return param[data_key]
        return None
    return data.get(data_key)


def _list2map(data):
    if not isinstance(data, list):
        return data
    new_data = {}
    for obj in data:
        for key in obj:
            new_data[key] = obj[key]
    new_data['raw_data'] = data
    return new_data
