"""Library to handle connection with Xiaomi Gateway"""
import socket
import json
import logging
import platform
import struct
from collections import defaultdict
from threading import Thread
from Crypto.Cipher import AES

_LOGGER = logging.getLogger(__name__)


class PyXiaomiGateway(object):
    """PyXiami."""
    MULTICAST_ADDRESS = '224.0.0.50'
    MULTICAST_PORT = 9898
    GATEWAY_DISCOVERY_PORT = 4321
    SOCKET_BUFSIZE = 1024

    gateways = defaultdict(list)

    def __init__(self, callback_func, gateways_config, interface):

        self.callback_func = callback_func
        self._listening = False
        self._mcastsocket = None
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        if interface != 'any':
            self._socket.bind((interface, 0))

        self._threads = []
        self._gateways_config = gateways_config
        self._interface = interface

    # pylint: disable=too-many-branches
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
            key = gateway.get('key')

            if not (host and port and sid):
                continue

            try:
                ip_address = socket.gethostbyname(host)
                _LOGGER.info(
                    'Xiaomi Gateway %s configured at IP %s:%s',
                    sid, ip_address, port)

                self.gateways[ip_address] = XiaomiGateway(
                    ip_address, port, sid, key, self._socket)
            except OSError as error:
                _LOGGER.error(
                    "Could not resolve %s: %s", host, error)

        try:
            _socket.sendto('{"cmd":"whois"}'.encode(),
                           (self.MULTICAST_ADDRESS, self.GATEWAY_DISCOVERY_PORT))

            while True:
                data, _ = _socket.recvfrom(1024)
                if len(data) is None:
                    continue

                resp = json.loads(data.decode())
                if resp["cmd"] != 'iam':
                    _LOGGER.error("Response does not match return cmd")
                    continue

                if resp["model"] != 'gateway':
                    _LOGGER.error("Response must be gateway model")
                    continue

                ip_add = resp["ip"]
                if ip_add in self.gateways:
                    continue

                gateway_key = ''
                for gateway in self._gateways_config:
                    sid = gateway['sid']
                    key = gateway['key']
                    if sid is None or sid == resp["sid"]:
                        gateway_key = key

                sid = resp["sid"]
                port = resp["port"]

                _LOGGER.info('Xiaomi Gateway %s found at IP %s', sid, ip_add)

                self.gateways[ip_add] = XiaomiGateway(ip_add, port, sid, gateway_key, self._socket)

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
            mreq = struct.pack("4sl", socket.inet_aton(self.MULTICAST_ADDRESS), socket.INADDR_ANY)

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

        if self._socket is not None:
            _LOGGER.info('Closing socket')
            self._socket.close()
            self._socket = None

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
                    _LOGGER.error('Unknown gateway ip %s', ip_add)
                    continue

                cmd = data['cmd']
                if cmd == 'heartbeat' and data['model'] == 'gateway':
                    gateway.token = data['token']
                elif cmd == 'report' or cmd == 'heartbeat':
                    _LOGGER.debug('MCAST (%s) << %s', cmd, data)

                    if cmd == 'heartbeat' and data['model'] in ['motion', 'sensor_motion.aq2']:
                        _LOGGER.debug(
                            'Skipping heartbeat of the motion sensor.'
                            ' It can introduce an incorrect state because of a firmware bug.')
                    else:
                        self.callback_func(gateway.push_data, data)
                else:
                    _LOGGER.error('Unknown multicast data: %s', data)
            # pylint: disable=broad-except
            except Exception:
                _LOGGER.error('Cannot process multicast message: %s', data)
                continue


# pylint: disable=too-many-instance-attributes
class XiaomiGateway(object):
    """Xiaomi Gateway Component"""

    # pylint: disable=too-many-arguments
    def __init__(self, ip_adress, port, sid, key, sock):

        self.ip_adress = ip_adress
        self.port = int(port)
        self.sid = sid
        self.key = key
        self.devices = defaultdict(list)
        self.callbacks = defaultdict(list)
        self.token = None
        self._socket = sock

        trycount = 5
        for _ in range(trycount):
            _LOGGER.info('Discovering Xiaomi Devices')
            if self._discover_devices():
                break

    def _discover_devices(self):

        cmd = '{"cmd" : "get_id_list"}'
        resp = self._send_cmd(cmd, "get_id_list_ack")
        if resp is None or "token" not in resp or "data" not in resp:
            return False
        self.token = resp['token']
        sids = json.loads(resp["data"])
        sids.append(self.sid)

        _LOGGER.info('Found %s devices', len(sids))

        device_types = {
            'sensor': ['sensor_ht', 'gateway', 'weather.v1', 'sensor_motion.aq2'],
            'binary_sensor': ['magnet', 'sensor_magnet.aq2', 'motion', 'sensor_motion.aq2', 'switch',
                              'sensor_switch.aq2', '86sw1', '86sw2', 'cube', 'smoke', 'natgas', 'sensor_wleak.aq1'],
            'switch': ['plug', 'ctrl_neutral1', 'ctrl_neutral2', 'ctrl_ln1', 'ctrl_ln2', '86plug'],
            'light': ['gateway'],
            'cover': ['curtain']}

        for sid in sids:
            cmd = '{"cmd":"read","sid":"' + sid + '"}'
            resp = self._send_cmd(cmd, "read_ack")
            if resp is None:
                continue
            data = json.loads(resp["data"])
            if "error" in data:
                _LOGGER.error("Not a valid device. Check the mac adress and update the firmware.")
                continue

            model = resp["model"]
            supported = False

            for device_type in device_types:
                if model in device_types[device_type]:
                    supported = True
                    xiaomi_device = {
                        "model": model,
                        "sid": resp["sid"],
                        "short_id": resp["short_id"],
                        "data": data}
                    self.devices[device_type].append(xiaomi_device)
                    _LOGGER.debug('Registering device %s, %s as: %s', sid, model, device_type)

            if not supported:
                _LOGGER.error('Unsupported device found! Please create an issue at '
                              'https://github.com/Danielhiversen/PyXiaomiGateway/issues '
                              'and provide the following data: %s', resp)
                continue
        return True

    def _send_cmd(self, cmd, rtn_cmd):
        try:
            self._socket.settimeout(10.0)
            _LOGGER.debug(">> %s", cmd.encode())
            self._socket.sendto(cmd.encode(), (self.ip_adress, self.port))
            data, _ = self._socket.recvfrom(1024)
        except socket.timeout:
            _LOGGER.error("Cannot connect to Gateway")
            return None
        if data is None:
            _LOGGER.error("No response from Gateway")
            return None
        resp = json.loads(data.decode())
        _LOGGER.debug("<< %s", resp)
        if resp['cmd'] != rtn_cmd:
            _LOGGER.error("Non matching response. Expecting %s, but got %s", rtn_cmd, resp['cmd'])
            return None
        return resp

    def write_to_hub(self, sid, **kwargs):
        """Send data to gateway to turn on / off device"""
        data = {}
        for key in kwargs:
            data[key] = kwargs[key]
        if self.token is None:
            return False
        data['key'] = self._get_key()
        cmd = {}
        cmd['cmd'] = 'write'
        cmd['sid'] = sid
        cmd['data'] = data
        cmd = json.dumps(cmd)
        resp = self._send_cmd(cmd, "write_ack")
        return _validate_data(resp)

    def get_from_hub(self, sid):
        """Get data from gateway"""
        cmd = '{ "cmd":"read","sid":"' + sid + '"}'
        resp = self._send_cmd(cmd, "read_ack")
        return self.push_data(resp)

    def push_data(self, data):
        """Push data broadcasted from gateway to device"""
        if not _validate_data(data):
            return False
        jdata = json.loads(data['data'])
        if jdata is None:
            return False
        sid = data['sid']
        for func in self.callbacks[sid]:
            func(jdata)
        return True

    def _get_key(self):
        """Get key using token from gateway"""
        init_vector = bytes(bytearray.fromhex('17996d093d28ddb3ba695a2e6f58562e'))
        encryptor = AES.new(self.key.encode(), AES.MODE_CBC, IV=init_vector)
        ciphertext = encryptor.encrypt(self.token.encode())
        return ''.join('{:02x}'.format(x) for x in ciphertext)


def _validate_data(data):
    if data is None or "data" not in data:
        _LOGGER.error('No data in response from hub %s', data)
        return False
    if 'error' in data['data']:
        _LOGGER.error('Got error element in data %s', data['data'])
        return False
    return True
