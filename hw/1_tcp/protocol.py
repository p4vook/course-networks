import socket
from random import randint 
from enum import Enum


class UDPBasedProtocol:
    def __init__(self, *, local_addr, remote_addr):
        self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)

    def sendto(self, data):
        return self.udp_socket.sendto(data, self.remote_addr)

    def recvfrom(self, n):
        msg, addr = self.udp_socket.recvfrom(n)
        return msg

    def close(self):
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


class MyTCPProtocol(UDPBasedProtocol):
    class PacketMeta:
        NUM_SIZE = 8
        META_SIZE = 4 * NUM_SIZE

        typ: PacketType
        start: int
        end: int
        seq: int

        def __init__(self, typ, start, end, seq):
            self.typ = typ
            self.start = start
            self.end = end
            self.seq = seq
        
        def to_bytes(self):
            return number_to_bytes(self.typ, self.NUM_SIZE) + \
                   number_to_bytes(self.start, self.NUM_SIZE) + \
                   number_to_bytes(self.end, self.NUM_SIZE) + \
                   number_to_bytes(self.seq, self.NUM_SIZE)

    SEGMENT_SIZE = 4000
    PACKET_SIZE = PacketMeta.META_SIZE + SEGMENT_SIZE

    def bytes_to_meta(self, byte_meta: bytes) -> PacketMeta:
        NS = self.PacketMeta.NUM_SIZE
        MS = self.PacketMeta.META_SIZE
        return self.PacketMeta(*[bytes_to_number(byte_meta[i:i+NS]) for i in range(0, MS, NS)])

    class TCPReader:
        udp: UDPBasedProtocol
        buf = bytes()

        def __init__(self, protocol: UDPBasedProtocol):
            self.udp = protocol
        
        def read(self):
            packet_bytes = self.udp.recvfrom(MyTCPProtocol.PACKET_SIZE)
            meta = MyTCPProtocol.bytes_to_meta(packet_bytes)
            while meta.typ != PacketType.SYN:
                packet_bytes = self.udp.recvfrom(MyTCPProtocol.PACKET_SIZE)
                meta = MyTCPProtocol.bytes_to_meta(packet_bytes)
            while meta.typ != PacketType.FIN:
                while meta.typ != PacketType.DATA:
                    packet_bytes = self.udp.recvfrom(MyTCPProtocol.PACKET_SIZE)
                    meta = MyTCPProtocol.bytes_to_meta(packet_bytes)


    class TCPWriter:
        udp: UDPBasedProtocol

        def __init__(self, protocol: UDPBasedProtocol):
            self.udp = protocol

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def send(self, data: bytes):
        return self.sendto(data)

    def recv(self, n: int):
        return self.recvfrom(n)
    
    def close(self):
        super().close()

