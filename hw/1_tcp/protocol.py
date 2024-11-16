import socket
from random import randint 
from enum import Enum
from threading import Thread
from datetime import datetime
from select import select
from typing import Callable
from time import sleep
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
    SYNACK = 3
    ACK = 4
    FIN = 5


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
    
    def __iter__(self) -> iter:
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

    def __iter__(self) -> iter:
        return iter((self.meta, self.segment))

class PacketProtocol:
    DEFAULT_DELAY_US = 2000
    SYN_TIMEOUT = 0.1
    FIN_TIMEOUT = 0.1
    STEP = 0.001

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


def in_seq_segment(seq: int, seq_start: int, cur_seq: int) -> bool:
    SEQ_TOLERANCE = 10000
    cur_seq = (cur_seq + SEQ_TOLERANCE) & ((1 << 32) - 1)
    if seq_start <= cur_seq:
        return seq_start <= seq and seq <= cur_seq
    else:
        return seq_start <= seq or seq <= cur_seq


class TCPReader:
    class State(Enum):
        SYN_WAIT = 10
        ACK_WAIT = 20
        ESTABLISHED = 30
        FIN_WAIT = 40
        TIME_OUT = 50

    SYN_WAIT_US = 20*10**6
    ACK_WAIT_US = 100*10**3
    ESTABLISHED_WAIT_US = 3*10**6
    FIN_WAIT_US = 100*10**3

    protocol: PacketProtocol
    state: State = State.SYN_WAIT
    buf: bytes = bytes()
    buf_ptr = 0
    seq_start = 0
    last_seq = 0
    wait_start: datetime = datetime.now()
    first_unreceived = 0

    def __init__(self, protocol: PacketProtocol) -> None:
        self.protocol = protocol
    
    def valid_seq(self, seq: int) -> bool:
        return in_seq_segment(seq, self.seq_start, self.last_seq)

    def handle_input(self, input: Packet | None) -> None:
        now = datetime.now()
        if self.state == self.State.SYN_WAIT:
            if not input or input.meta.typ != PacketType.SYN:
                if (now - self.wait_start).microseconds > self.SYN_WAIT_US:
                    self.state = self.State.TIME_OUT
                return
            self.seq_start = input.meta.seq
            self.last_seq = self.seq_start
            self.protocol.send_packet(Packet(PacketMeta(PacketType.SYNACK, 0, 0, self.seq_start)))
            self.wait_start = now
            self.fisrt_unreceived = 0
            self.state = self.State.ACK_WAIT
        elif self.state == self.State.ACK_WAIT:
            if not input or input.meta.typ != PacketType.ACK or input.meta.seq != self.seq_start:
                if (now - self.wait_start).microseconds > self.ACK_WAIT_US:
                    self.state = self.State.SYN_WAIT
                return 
            self.wait_start = now
            self.state = self.State.ESTABLISHED
        elif self.state == self.State.ESTABLISHED:
            if not input \
               or not (input.meta.typ == PacketType.DATA and self.valid_seq(input.meta.seq)) \
               or not (input.meta.typ == PacketType.FIN and input.meta.seq == self.seq_start):
                if (now - self.wait_start).microseconds > self.ACK_WAIT_US:
                    self.state = self.State.SYN_WAIT
                return
            self.wait_start = now
            if input.meta.typ == PacketType.FIN:
                self.protocol.send_packet(Packet(PacketMeta(PacketType.FIN, 0, 0, self.seq_start)))
                self.state = self.State.ACK_WAIT
            if input.meta.start > self.first_unreceived:
                return
            if self.first_unreceived < input.meta.end:
                self.buf += input.segment[self.first_unreceived-input.meta.start:input.meta.end]
                self.first_unreceived = input.meta.end
            self.protocol.send_packet(Packet(PacketMeta(PacketType.ACK, input.meta.start, input.meta.end, input.meta.seq)))
        elif self.state == self.State.ACK_WAIT:
            if not input or not (input.meta.typ == PacketType.ACK and input.meta.seq == self.seq_start):
                if (now - self.wait_start).microseconds() > self.ACK_WAIT_US:
                    self.wait_start = now
                    self.state = self.State.ESTABLISHED
                return
            self.wait_start = now
            self.state = self.State.SYN_WAIT

    def do_read(self, n: int) -> bytes:
        while self.buf_ptr + n < len(self.buf):
            sleep(PacketProtocol.STEP)
        return self.buf[self.buf_ptr:self.buf_ptr + n]


class TCPWriter:
    class State(Enum):
        DEFAULT = 00
        INIT = 10
        SYNACK_WAIT = 20
        ESTABLISHED = 30
        FIN_WAIT = 40
        FINISHED = 50
    
    state: State = State.DEFAULT
    protocol: PacketProtocol

    def __init__(self, protocol: PacketProtocol) -> None:
        self.protocol = protocol

    def handle_input(self, input: Packet | None) -> None:
        pass 
    
    def do_write(self, data: bytes) -> int:
        self.state = self.State.INIT
        while self.state != self.State.FINISHED:
            sleep(PacketProtocol.STEP)
        return len(data)


class MyTCPProtocol(UDPBasedProtocol):
    protocol: PacketProtocol
    actor: Thread
    reader: TCPReader
    writer: TCPWriter

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.protocol = PacketProtocol(self)
        self.actor = Thread(target=self.act)
        self.reader = TCPReader(self.protocol)
        self.writer = TCPWriter(self.protocol)
    
    def act(self):
        while not (self.reader.state == TCPReader.State.TIME_OUT and self.writer.state == TCPWriter.State.FINISHED):
            packet = self.protocol.get_one_packet(timeout=PacketProtocol.STEP)
            self.reader.handle_input(packet)
            self.writer.handle_input(packet)

    def send(self, data: bytes) -> int:
        return self.writer.do_write(data)

    def recv(self, n: int) -> bytes:
        return self.reader.do_read(n)
    
    def close(self):
        super().close()

