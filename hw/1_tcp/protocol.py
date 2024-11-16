import socket
from random import randint 
from enum import Enum
from threading import Thread
from datetime import datetime
from select import select
from typing import Callable
import logging

logging.basicConfig(filename=f"/var/log/app/tcp-{datetime.now().isoformat()}.log", level=logging.DEBUG)

class UDPBasedProtocol:
    def __init__(self, *, local_addr, remote_addr) -> None:
        self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.local_addr = local_addr
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)
        self.logger = logging.Logger("UDP")
        self.logger.info(f"Initialized socket {self.local_addr} <-> {self.remote_addr}")

    def sendto(self, data) -> int:
        self.logger.debug(f"Sending {len(data)} bytes {self.local_addr} -> {self.remote_addr}")
        res = self.udp_socket.sendto(data, self.remote_addr)
        self.logger.debug(f"Sent {len(data)} bytes {self.local_addr} -> {self.remote_addr}")
        return res

    def recvfrom(self, n) -> bytes:
        self.logger.debug(f"Receiving {n} bytes on {self.local_addr}")
        msg, addr = self.udp_socket.recvfrom(n)
        self.logger.debug(f"Received {len(msg)} bytes {addr} -> {self.local_addr}")
        return msg

    def close(self) -> None:
        self.udp_socket.close()


def number_to_bytes(num: int, len: int) -> bytes:
    return bytes([(num >> (8 * i)) & 0xFF for i in range(len)])


def bytes_to_number(num_bytes: bytes) -> int:
    return sum([byte << (8 * i) for (i, byte) in enumerate(num_bytes)])


class PacketType(Enum):
    DATA = 1
    SYN = 2
    ACK = 3
    FIN = 4


class PacketMeta:
    META_SIZE = 24

    typ: PacketType
    seq: int
    start: int
    end: int

    def __init__(self, typ: PacketType, start: int, end: int, seq: int) -> None:
        self.typ = typ
        self.start = start
        self.end = end
        self.seq = seq
    
    def __iter__(self):
        return iter((self.typ, self.start, self.end, self.seq))

    def to_bytes(self) -> bytes:
        return number_to_bytes(self.typ.value, 4) + \
               number_to_bytes(self.seq, 4) + \
               number_to_bytes(self.start, 8) + \
               number_to_bytes(self.end, 8)


def bytes_to_meta(byte_meta: bytes) -> PacketMeta:
    assert len(byte_meta) == PacketMeta.META_SIZE
    typ = bytes_to_number(byte_meta[:4])
    seq = bytes_to_number(byte_meta[4:8])
    start = bytes_to_number(byte_meta[8:16])
    end = bytes_to_number(byte_meta[16:24])
    return PacketMeta(PacketType(typ), start, end, seq)


class Packet:
    SEGMENT_SIZE = 4000

    meta: PacketMeta
    segment: bytes

    def __init__(self, meta: PacketMeta, segment: bytes = bytes()) -> None:
        if meta.typ == PacketType.DATA:
            assert len(segment) == self.SEGMENT_SIZE
        else: 
            assert len(segment) == 0
        self.meta = meta
        self.segment = segment

    def __iter__(self):
        return iter((self.meta, self.segment))

class PacketProtocol:
    DEFAULT_DELAY_US = 2000
    SYN_TIMEOUT = 0.1
    FIN_TIMEOUT = 0.1

    logger = logging.Logger("PacketProtocol")
    hooks: list[Callable[[Packet], None]] = []

    udp: UDPBasedProtocol

    def __init__(self, udp: UDPBasedProtocol) -> None:
        self.udp = udp
        self.logger.info(f"Initialized protocol {udp.local_addr} -> {udp.remote_addr}")
    
    def receive_packet(self) -> Packet:
        meta_bytes = self.udp.recvfrom(PacketMeta.META_SIZE)
        packet_meta = bytes_to_meta(meta_bytes)
        segment_bytes = bytes()
        if packet_meta.typ == PacketType.DATA:
            segment_bytes = self.udp.recvfrom(Packet.SEGMENT_SIZE)
        res = Packet(packet_meta, segment_bytes)
        self.logger.debug(f"Received packet {packet_meta} with length {len(segment_bytes)}")
        return res
    
    def send_packet(self, packet: Packet) -> bool:
        packet_bytes = packet.meta.to_bytes() + packet.segment
        self.logger.debug(f"Sending packet {packet.meta} with length {len(packet.segment)}")
        return self.udp.sendto(packet_bytes) == len(packet_bytes)
    
    def get_one_packet(self, timeout: float | None = None):
        if timeout:
            self.logger.debug(f"Selecting for packet with timeout {timeout}")
            readable, _, _ = select([self.udp.udp_socket], [], [], timeout)
            self.logger.debug(f"Select finished, result {readable != []}")
            if not readable:
                return None
        return self.receive_packet()
    
    def delay_step(self, previous_delay: int, current_delay: int) -> int:
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
        meta, segment = self.protocol.get_packet(typ = [PacketType.SYN])
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
            self.protocol.send_packet(Packet(response_meta))
            meta, segment = self.protocol.get_packet(typ=[PacketType.DATA, PacketType.FIN])
        self.protocol.send_packet(Packet(meta))
    
    def read(self, n: int) -> bytes:
        self.reader_thread.join()
        assert self.buf_ptr + n <= len(self.buf)
        return self.buf[self.buf_ptr:self.buf_ptr + n]

class MyTCPProtocol(UDPBasedProtocol):
    protocol: PacketProtocol
    reader: TCPReader
    writer: TCPWriter

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.protocol = PacketProtocol(self)
        self.reader = TCPReader(self.protocol)
        self.writer = TCPWriter(self.protocol)

    def send(self, data: bytes) -> int:
        return self.writer.write(data)

    def recv(self, n: int) -> bytes:
        return self.reader.read(n)
    
    def close(self):
        super().close()

