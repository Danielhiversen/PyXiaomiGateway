"""Library to handle connection with Xiaomi Gateway"""
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


class XiaomiGatewayDiscovery:
    """PyXiami."""
    # pylint: disable=too-many-instance-attributes
    MULTICAST_ADDRESS = '224.0.0.50'
    MULTICAST_PORT = 9898
    GATEWAY_DISCOVERY_PORT = 4321
    SOCKET_BUFSIZE = 1024

    def __init__(self, callback_func, gateways_config, interface,
                 device_discovery_retries=DEFAULT_DISCOVERY_RETRIES):

        self.disabled_gateways = []
        self.gateways = defaultdict(list)
        self.callback_func = callback_func
        self._listening = False
        self._mcastsocket = None
        self._threads = []
        self._gateways_config = gateways_config
        self._interface = interface
        self._device_discovery_retries = device_discovery_retries

    # pylint: disable=too-many-branches, too-many-locals, too-many-statements
    def discover_gateways(self):
        """Discover gateways using multicast"""

        _socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _socket.settimeout(5.0)
        if self._interface != 'any':
            _socket.bind((self._interface, 0))

        for gateway in self._gateways_config:
            host = gateway.get('host')
            port = gateway.get('port')
            sid = gateway.get('sid')

            if not (host and port and sid):
                continue
            try:
                ip_address = socket.gethostbyname(host)
                if gateway.get('disable'):
                    _LOGGER.info(
                        'Xiaomi Gateway %s is disabled by configuration', sid)
                    self.disabled_gateways.append(ip_address)
                    continue
                _LOGGER.info(
                    'Xiaomi Gateway %s configured at IP %s:%s',
                    sid, ip_address, port)

                self.gateways[ip_address] = XiaomiGateway(
                    ip_address, port, sid,
                    gateway.get('key'), self._device_discovery_retries,
                    self._interface, gateway.get('proto'))
            except OSError as error:
                _LOGGER.error(
                    "Could not resolve %s: %s", host, error)

        try:
            _socket.sendto('{"cmd":"whois"}'.encode(),
                           (self.MULTICAST_ADDRESS, self.GATEWAY_DISCOVERY_PORT))

            while True:
                data, (ip_add, _) = _socket.recvfrom(1024)
                if len(data) is None or ip_add in self.gateways:
                    continue

                if ip_add in self.gateways.keys() or ip_add in self.disabled_gateways:
                    continue

                resp = json.loads(data.decode())
                if resp["cmd"] != 'iam':
                    _LOGGER.error("Response does not match return cmd")
                    continue

                if resp["model"] not in GATEWAY_MODELS:
                    _LOGGER.error("Response must be gateway model")
                    continue

                disabled = False
                gateway_key = None
                for gateway in self._gateways_config:
                    sid = gateway.get('sid')
                    if sid is None or sid == resp["sid"]:
                        gateway_key = gateway.get('key')
                    if sid and sid == resp['sid'] and gateway.get('disable'):
                        disabled = True

                sid = resp["sid"]
                if disabled:
                    _LOGGER.info("Xiaomi Gateway %s is disabled by configuration",
                                 sid)
                    self.disabled_gateways.append(ip_add)
                else:
                    _LOGGER.info('Xiaomi Gateway %s found at IP %s', sid, ip_add)
                    self.gateways[ip_add] = XiaomiGateway(
                        ip_add, resp["port"], sid, gateway_key,
                        self._device_discovery_retries, self._interface,
                        resp["proto_version"] if "proto_version" in resp else None)

        except socket.timeout:
            _LOGGER.info("Gateway discovery finished in 5 seconds")
            _socket.close()

    def _create_mcast_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if self._interface != 'any':
            if platform.system() != "Windows":
                sock.bind((self.MULTICAST_ADDRESS, self.MULTICAST_PORT))
            else:
                sock.bind((self._interface, self.MULTICAST_PORT))

            mreq = socket.inet_aton(self.MULTICAST_ADDRESS) + socket.inet_aton(self._interface)
        else:
            if platform.system() != "Windows":
                sock.bind((self.MULTICAST_ADDRESS, self.MULTICAST_PORT))
            else:
                sock.bind(('', self.MULTICAST_PORT))
            mreq = struct.pack("=4sl", socket.inet_aton(self.MULTICAST_ADDRESS), socket.INADDR_ANY)

        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        return sock

    def listen(self):
        """Start listening."""

        _LOGGER.info('Creating Multicast Socket')
        self._mcastsocket = self._create_mcast_socket()
        self._listening = True
        thread = Thread(target=self._listen_to_msg, args=())
        self._threads.append(thread)
        thread.daemon = True
        thread.start()

    def stop_listen(self):
        """Stop listening."""
        self._listening = False

        if self._mcastsocket is not None:
            _LOGGER.info('Closing multisocket')
            self._mcastsocket.close()
            self._mcastsocket = None

        for thread in self._threads:
            thread.join()

    def _listen_to_msg(self):
        while self._listening:
            if self._mcastsocket is None:
                continue
            data, (ip_add, _) = self._mcastsocket.recvfrom(self.SOCKET_BUFSIZE)
            try:
                data = json.loads(data.decode("ascii"))
                gateway = self.gateways.get(ip_add)
                if gateway is None:
                    if ip_add not in self.disabled_gateways:
                        _LOGGER.error('Unknown gateway ip %s', ip_add)
                    continue

                cmd = data['cmd']
                if cmd == 'heartbeat' and data['model'] in GATEWAY_MODELS:
                    gateway.token = data['token']
                elif cmd in ('report', 'heartbeat'):
                    _LOGGER.debug('MCAST (%s) << %s', cmd, data)
                    self.callback_func(gateway.push_data, data)
                else:
                    _LOGGER.error('Unknown multicast data: %s', data)
            # pylint: disable=broad-except
            except Exception:
                _LOGGER.error('Cannot process multicast message: %s', data)
                continue


# pylint: disable=too-many-instance-attributes
class XiaomiGateway:
    """Xiaomi Gateway Component"""

    # pylint: disable=too-many-arguments
    def __init__(self, ip_adress, port, sid, key, discovery_retries, interface, proto=None):

        self.ip_adress = ip_adress
        self.port = int(port)
        self.sid = sid
        self.key = key
        self.devices = defaultdict(list)
        self.callbacks = defaultdict(list)
        self.token = None
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
                              '86sw1', 'sensor_86sw1', 'sensor_86sw1.aq1', 'remote.b186acn01',
                              '86sw2', 'sensor_86sw2', 'sensor_86sw2.aq1', 'remote.b286acn01',
                              'cube', 'sensor_cube', 'sensor_cube.aqgl01',
                              'smoke', 'sensor_smoke',
                              'natgas', 'sensor_natgas',
                              'sensor_wleak.aq1',
                              'vibration', 'vibration.aq1'],
            'switch': ['plug',
                       'ctrl_neutral1', 'ctrl_neutral1.aq1',
                       'ctrl_neutral2', 'ctrl_neutral2.aq1',
                       'ctrl_ln1', 'ctrl_ln1.aq1',
                       'ctrl_ln2', 'ctrl_ln2.aq1',
                       '86plug', 'ctrl_86plug', 'ctrl_86plug.aq1'],
            'light': ['gateway', 'gateway.v3'],
            'cover': ['curtain'],
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
            data, _ = _socket.recvfrom(1024)
        except socket.timeout:
            _LOGGER.error("Cannot connect to Gateway")
            return None
        finally:
            _socket.close()
        if data is None:
            _LOGGER.error("No response from Gateway")
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
