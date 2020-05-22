import random
import socket
from enum import IntEnum


class IcmpType(IntEnum):
    ECHO_REPLY = 0
    ECHO_REQUEST = 8
    TTL_EXCEEDED = 11


class ICMPPacket:
    def __init__(self, type_: int, code: int, other: bytes = None, **kwargs):
        self.type = type_
        self.code = code
        self.other = other
        if (self.type == IcmpType.ECHO_REQUEST
                or self.type == IcmpType.ECHO_REPLY):
            self.id = random.randint(0, 2 ** 16 - 1)
            self.sequence_number = random.randint(0, 2 ** 16 - 1)
        if self.type == IcmpType.TTL_EXCEEDED:
            self.child = None

        for key, item in kwargs.items():
            setattr(self, key, item)

    @classmethod
    def extract_icmp_data(cls, data):
        version = (data[0] & 0xf0) // 16
        if version == 4:
            header_length = (data[0] & 0x0f) * 4
            if data[9] == 1:
                return data[header_length:]
        return None

    @classmethod
    def from_bytes(cls, data):
        if data[0] == IcmpType.TTL_EXCEEDED:
            child = ICMPPacket.from_bytes(
                ICMPPacket.extract_icmp_data(data[8:]))
            return ICMPPacket(data[0], data[1], child=child)
        if data[0] == IcmpType.ECHO_REPLY or data[0] == IcmpType.ECHO_REQUEST:
            return ICMPPacket(data[0], data[1],
                              id=int.from_bytes(data[4:6], 'big'),
                              sequence_number=int.from_bytes(data[6:8], 'big'))

    def __bytes__(self):
        result = bytes([self.type, self.code]) + b'\0\0'
        if self.type == IcmpType.ECHO_REQUEST:
            result += (int.to_bytes(self.id, 2, 'big') +
                       int.to_bytes(self.sequence_number, 2, 'big'))
        return ICMPPacket.with_inserted_checksum(result)

    @classmethod
    def with_inserted_checksum(cls, packet):
        checksum = sum([int.from_bytes(packet[_:_ + 2], "big") for _ in
                        range(0, len(packet), 2)])
        while checksum > 0xffff:
            checksum = (checksum & 0xffff) + (checksum >> 16)
        return (packet[:2] + int.to_bytes(0xffff - checksum, 2, 'big')
                + packet[4:])

    def is_answer(self, other):
        if other is None:
            return False
        if other.type == IcmpType.ECHO_REPLY:
            return (self.id == other.id
                    and self.sequence_number == other.sequence_number)
        if other.type == IcmpType.TTL_EXCEEDED:
            return (other.child is not None and self.id == other.child.id and
                    self.sequence_number == other.child.sequence_number)


def get_icmp_listener(interf_ip, timeout=0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.bind((interf_ip, 0))
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    sock.settimeout(timeout)
    return sock


def get_trace(inter_ip, dest_ip, depth=15, timeout_for_step=2):
    sock = get_icmp_listener(inter_ip, timeout_for_step)
    packet = ICMPPacket(IcmpType.ECHO_REQUEST, 0,
                        id=random.randint(0, 2 ** 16), sequence_number=15)
    for i in range(1, depth + 1):
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, i)
        packet.sequence_number += 1
        sock.sendto(bytes(packet), (dest_ip, 0))
        result = None
        while not result:
            try:
                response_data, addr = sock.recvfrom(65535)
                response = ICMPPacket.from_bytes(
                    ICMPPacket.extract_icmp_data(response_data))
                if addr[0] == inter_ip or not packet.is_answer(response):
                    continue
                result = addr[0]
            except socket.error:
                result = '*'
            break
        yield result
        if result == dest_ip:
            break
