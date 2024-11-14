import socket
from random import randint 
from enum import Enum
from threading import Thread
from datetime import datetime
from select import select


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
    SYNACK = 3
    ACK = 4
    FIN = 5


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


class Packet:
    meta: PacketMeta
    segment: bytes


class PacketProtocol:
    SEGMENT_SIZE = 4000
    PACKET_SIZE = PacketMeta.META_SIZE + SEGMENT_SIZE

    DEFAULT_DELAY_US = 2000
    SYN_TIMEOUT_US = 100000
    FIN_TIMEOUT_US = 100000

    udp: UDPBasedProtocol

    def __init__(self, udp) -> None:
        self.udp = udp

    def receive_packet(self) -> Packet:
        packet_bytes = self.udp.recvfrom(self.PACKET_SIZE)
        packet_meta = bytes_to_meta(packet_bytes[:PacketMeta.META_SIZE])
        return packet_meta, packet_bytes[self.PACKET_SIZE:]
    
    def send_packet(self, packet: Packet) -> bool:
        packet_bytes = packet.meta.to_bytes() + packet.segment
        assert len(packet_bytes) == self.PACKET_SIZE
        return self.udp.sendto(packet_bytes) == self.PACKET_SIZE

    def delay_step(previous_delay: int, current_delay: int) -> int:
        return (previous_delay * 4 + current_delay) // 5


class TCPReader:
    protocol: PacketProtocol
    buf = bytes()
    reader_thread: Thread
    buf_ptr = 0

    def __init__(self, protocol: PacketProtocol) -> None:
        self.protocol = protocol
        self.reader_thread = Thread(target=self.read_to_buf)
        self.reader_thread.start()
    
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
        self.protocol.send_packet(Packet(meta, bytes(PacketProtocol.PACKET_SIZE)))
    
    def read(self, n: int) -> bytes:
        self.reader_thread.join()
        assert self.buf_ptr + n <= len(self.buf)
        return self.buf[self.buf_ptr:self.buf_ptr + n]


class TCPWriter:
    protocol: PacketProtocol
    seq_start: int
    cur_seq: int
    packet_sent_ts: dict[int, datetime]
    cur_delay_us: int = PacketProtocol.DEFAULT_DELAY_US

    def __init__(self, protocol: PacketProtocol) -> None:
        self.protocol = protocol
    
    def get_one_packet(self,
                       timeout: int | None) -> Packet | None:
        if timeout:
            if not select.select([self.protocol.udp], [], [], timeout):
                return None
        return self.protocol.receive_packet()
    
    def get_packet(self, 
                   blocking: bool = True,
                   seq: int | None = None,
                   timeout: int | None = None


    def write(self, buf: bytes) -> int:
        n = len(buf)
        while 
        self.protocol.send_packet()
        return n

class MyTCPProtocol(UDPBasedProtocol):
    protocol: PacketProtocol
    reader: TCPReader
    writer: TCPWriter

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.protocol = PacketProtocol(self.udp_socket)
        self.reader = TCPReader(self.protocol)
        self.writer = TCPWriter(self.protocol)

    def send(self, data: bytes):
        return self.sendto(data)

    def recv(self, n: int):
        return self.recvfrom(n)
    
    def close(self):
        super().close()

