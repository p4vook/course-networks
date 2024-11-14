import socket
from random import randint 
from enum import Enum


class UDPBasedProtocol:
    def __init__(self, *, local_addr, remote_addr) -> None:
        self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)

    def sendto(self, data) -> int:
        return self.udp_socket.sendto(data, self.remote_addr)

    def recvfrom(self, n) -> bytes:
        msg, addr = self.udp_socket.recvfrom(n)
        return msg

    def close(self) -> None:
        self.udp_socket.close()


def number_to_bytes(num: int, len: int) -> bytes:
    return bytes([(num >> (8 * i)) & 0xFF for i in range(len)])


def bytes_to_number(bytearray: bytes) -> int:
    return sum([byte << (8 * i) for (i, byte) in enumerate(bytearray)])


class PacketType(Enum):
    DATA = 1
    SYN = 2
    ACK = 3
    FIN = 4


class PacketMeta:
    NUM_SIZE = 8
    META_SIZE = 4 * NUM_SIZE

    typ: PacketType
    start: int
    end: int
    seq: int

    def __init__(self, typ: PacketType, start: int, end: int, seq: int) -> None:
        self.typ = typ
        self.start = start
        self.end = end
        self.seq = seq
    
    def to_bytes(self) -> bytes:
        return number_to_bytes(self.typ.value, self.NUM_SIZE) + \
            number_to_bytes(self.start, self.NUM_SIZE) + \
            number_to_bytes(self.end, self.NUM_SIZE) + \
            number_to_bytes(self.seq, self.NUM_SIZE)


def bytes_to_meta(byte_meta: bytes) -> PacketMeta:
    NS = PacketMeta.NUM_SIZE
    MS = PacketMeta.META_SIZE
    typ, start, end, seq = (bytes_to_number(byte_meta[i:i+NS]) for i in range(0, MS, NS))
    return PacketMeta(PacketType(typ), start, end, seq)

class PacketProtocol:
    SEGMENT_SIZE = 4000
    PACKET_SIZE = PacketMeta.META_SIZE + SEGMENT_SIZE
    udp: UDPBasedProtocol

    def __init__(self, udp) -> None:
        self.udp = udp

    def receive_packet(self) -> tuple[PacketMeta, bytes]:
        packet_bytes = self.udp.recvfrom(self.PACKET_SIZE)
        packet_meta = bytes_to_meta(packet_bytes[:PacketMeta.META_SIZE])
        return (packet_meta, packet_bytes[self.PACKET_SIZE:])
    
    def send_packet(self, meta: PacketMeta, segment: bytes) -> bool:
        packet_bytes = meta.to_bytes() + segment
        assert len(packet_bytes) == self.PACKET_SIZE
        return self.udp.sendto(packet_bytes) == self.PACKET_SIZE


class TCPReader:
    protocol: PacketProtocol
    buf = bytes()
    buf_ptr = 0

    def __init__(self, protocol: PacketProtocol) -> None:
        self.protocol = protocol
    
    # Reads bytes into buf.
    def read_to_buf(self) -> None:
        meta, segment = self.protocol.receive_packet()
        while meta.typ != PacketType.SYN:
            meta, segment = self.protocol.receive_packet()
        while meta.typ != PacketType.FIN:
            first_unreceived = 0
            if meta.start > first_unreceived:
                continue
            if meta.end > first_unreceived:
                MS = PacketMeta.META_SIZE
                self.buf += segment[MS + (first_unreceived - meta.start):MS + meta.end]
                first_unreceived = meta.end
            response_meta = meta
            response_meta.typ = PacketType.ACK
            self.protocol.send_packet(response_meta, bytes(PacketProtocol.PACKET_SIZE))
            while meta.typ != PacketType.DATA and meta.typ != PacketType.FIN:
                meta, segment = self.protocol.receive_packet()
        self.protocol.send_packet(meta)
    
    def read(self, n: int) -> bytes:
        assert self.buf_ptr + n <= len(self.buf)
        return self.buf[self.buf_ptr:self.buf_ptr + n]


class MyTCPProtocol(UDPBasedProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def send(self, data: bytes):
        return self.sendto(data)

    def recv(self, n: int):
        return self.recvfrom(n)
    
    def close(self):
        super().close()

