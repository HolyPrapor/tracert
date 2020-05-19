import random
import socket
from enum import IntEnum


class IcmpType(IntEnum):
    ECHO_REPLY = 1
    ECHO_REQUEST = 8
    TTL_EXCEEDED = 11


def extract_data_from_icmp_packet(packet):
    version = (packet[0] & 0xf0) // 16
    if version == 4:
        header_length = (packet[0] & 0x0f) * 4
        if packet[9] == 1:
            return packet[header_length:]
    return None


def with_inserted_checksum(packet, offset=2):
    checksum = sum(int.from_bytes(packet[i:i + 2], 'big')
                   for i in range(0, len(packet), 2))
    while checksum > 0xffff:
        checksum = (checksum & 0xffff) + (checksum >> 16)
    return (packet[:offset] + int.to_bytes(0xffff - checksum, 2, 'big')
            + packet[offset + 2:])


class IcmpPacket:
    def __init__(self, **kwargs):
        self.type = None
        self.code = None
        self.id = None
        self.sequence_number = None
        self.child = None
        for key, value in kwargs.items():
            setattr(self, key, value)

        if self.type == IcmpType.ECHO_REQUEST or IcmpType.ECHO_REPLY:
            self.id = random.randint(0, 2 ** 16 - 1)
            self.sequence_number = random.randint(0, 2 ** 16 - 1)
        if self.type == IcmpType.TTL_EXCEEDED:
            self.child = None

    @classmethod
    def from_bytes(cls, data):
        if data[0] == IcmpType.TTL_EXCEEDED:
            child = IcmpPacket.from_bytes(
                extract_data_from_icmp_packet(data[8:]))
            return IcmpPacket(type=data[0], code=data[1], child=child)
        if data[0] == IcmpType.ECHO_REPLY or data[0] == IcmpType.ECHO_REQUEST:
            return IcmpPacket(type=data[0], code=data[1],
                              id=int.from_bytes(data[4:6], 'big'),
                              sequence_number=int.from_bytes(data[6:8], 'big'))

    def __bytes__(self):
        byte_view = bytes([self.type, self.code]) + b'\0\0'
        if self.type == IcmpType.ECHO_REQUEST:
            byte_view += (int.to_bytes(self.id, 2, 'big') +
                          int.to_bytes(self.sequence_number, 2, 'big'))
        return with_inserted_checksum(byte_view)

    def __str__(self):
        return repr(self)

    def __repr__(self):
        args = [f'ICMP({self.type}, {self.code}']
        if self.type == IcmpType.ECHO_REPLY or self.type == IcmpType.ECHO_REQUEST:
            args.append(f'id={self.id}, sequence_number={self.sequence_number}')
        if self.type == IcmpType.TTL_EXCEEDED:
            args.append(f'child={repr(self.child)}')
        return ',\n'.join(args) + ')'

    def is_needed_node(self, other):
        if other is None:
            return False
        if other.type == IcmpType.ECHO_REPLY:
            return (self.id == other.id and
                    self.sequence_number == other.sequence_number)
        if other.type == IcmpType.TTL_EXCEEDED:
            return (other.child is not None and self.id == other.child.id and
                    self.sequence_number == other.child.sequence_number)


def icmp_sniffer(interface_ip, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.bind((interface_ip, 0))
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    sock.settimeout(timeout)
    return sock


def get_trace(interface_ip, destination_ip, depth, step_timeout):
    sock = icmp_sniffer(interface_ip, step_timeout)

    icmp_packet = IcmpPacket(type=IcmpType.ECHO_REQUEST, code=0)
    for i in range(1, depth + 1):
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, i)
        icmp_packet.sequence_number += 1
        sock.sendto(bytes(icmp_packet), (destination_ip, 0))
        result = None
        while not result:
            try:
                data_, addr = sock.recvfrom(2 ** 16 - 1)
                response_packet = IcmpPacket.from_bytes(
                    extract_data_from_icmp_packet(data_))
                if addr[0] == interface_ip or not icmp_packet.is_needed_node(
                        response_packet):
                    continue
                result = addr[0]
            except socket.error:

                result = "BAD"
        yield result
        if result == destination_ip:
            break
