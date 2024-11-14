import socket
from random import randint 
from enum import Enum
from threading import Thread
from datetime import datetime
from select import select
from typing import Callable


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
    assert len(byte_meta) >= PacketMeta.META_SIZE
    typ = bytes_to_number(byte_meta[:4])
    seq = bytes_to_number(byte_meta[4:8])
    start = bytes_to_number(byte_meta[8:16])
    end = bytes_to_number(byte_meta[16:24])
    return PacketMeta(PacketType(typ), start, end, seq)


class Packet:
    SEGMENT_SIZE = 4000
    SIZE = PacketMeta.META_SIZE + SEGMENT_SIZE

    meta: PacketMeta
    segment: bytes

    def __init__(self, meta: PacketMeta, segment: bytes) -> None:
        assert len(segment) == self.SEGMENT_SIZE
        self.meta = meta
        self.segment = segment

    def __iter__(self):
        return iter((self.meta, self.segment))

class PacketProtocol:
    DEFAULT_DELAY_US = 2000
    SYN_TIMEOUT_US = 100000
    FIN_TIMEOUT_US = 100000

    udp: UDPBasedProtocol

    def __init__(self, udp) -> None:
        print("Initialized protocol...")
        self.udp = udp

    def receive_packet(self) -> Packet:
        packet_bytes = self.udp.recvfrom(Packet.SIZE)
        packet_meta = bytes_to_meta(packet_bytes[:PacketMeta.META_SIZE])
        return Packet(packet_meta, packet_bytes[PacketMeta.META_SIZE:])
    
    def send_packet(self, packet: Packet) -> bool:
        packet_bytes = packet.meta.to_bytes() + packet.segment
        print(f"Sending packet {packet.meta.typ, packet.meta.seq}")
        assert len(packet_bytes) == Packet.SIZE
        return self.udp.sendto(packet_bytes) == Packet.SIZE

    def get_one_packet(self,
                       timeout: int | None = None) -> Packet | None:
        if timeout:
            if not select([self.udp.udp_socket], [], [], timeout):
                return None
        return self.receive_packet()

    def get_packet(self, 
                   typ: list[PacketType] = [],
                   packet_filter: Callable[[Packet], bool] = lambda _: True,
                   timeout: int | None = None) -> Packet:
        packet = self.get_one_packet(timeout)
        typ_filter = lambda packet: typ is None or packet.meta.typ in typ
        while packet and not (typ_filter(packet) and packet_filter(packet)):
            # sloppy timeout handling but hopefully it won't break us
            packet = self.get_one_packet(timeout)
        if not packet:
            raise TimeoutError("Timeout waiting for packet")
        return packet

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
        self.protocol.get_packet(typ=[PacketType.SYN])
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
            self.protocol.send_packet(Packet(response_meta, bytes(Packet.SIZE)))
            meta, segment = self.protocol.get_packet(typ=[PacketType.DATA, PacketType.FIN])
        self.protocol.send_packet(Packet(meta, bytes(Packet.SIZE)))
    
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
        self.seq_start = randint(0, 2**32 - 1)
        self.cur_seq = self.seq_start

    def write(self, buf: bytes) -> int:
        n = len(buf)
        while True:
            meta = PacketMeta(PacketType.SYN, 0, 0, self.cur_seq)
            self.protocol.send_packet(Packet(meta, bytes(Packet.SEGMENT_SIZE)))
            try: 
                self.protocol.get_packet(typ=[PacketType.ACK],
                                         packet_filter=lambda packet: packet.meta.seq == self.cur_seq,
                                         timeout=self.protocol.SYN_TIMEOUT_US)
                break
            except TimeoutError:
                pass
        first_unack = 0
        while first_unack < n:
            iteration_start = datetime.now()
            for segment_start in range(first_unack, n, Packet.SEGMENT_SIZE):
                now = datetime.now()
                if (now - iteration_start).microseconds > 2 * self.cur_delay_us:
                    break
                segment_end = min(segment_start + Packet.SEGMENT_SIZE, n)
                self.cur_seq = (self.cur_seq + 1) % 2**32
                meta = PacketMeta(PacketType.DATA, segment_start, segment_end, self.cur_seq)
                packet_bytes = buf[segment_start:segment_end]
                packet_bytes += bytes(Packet.SEGMENT_SIZE - len(packet_bytes))
                self.protocol.send_packet(Packet(meta, packet_bytes))
        return n

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

