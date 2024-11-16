import socket
from random import randint 
from enum import Enum
from threading import Thread
from datetime import datetime
from select import select
from typing import Callable
from time import sleep
import logging
import logging.config


logNow = datetime.now().isoformat()

logging.config.dictConfig(
    {
        "version": 1,
        "formatters": {
            "precise": {
                "format": "%(asctime)s\t%(levelname)s\t%(name)s\t%(message)s",
            },
        },
        "handlers": {
            "debug_file": {
                "class": "logging.FileHandler",
                "formatter": "precise",
                "filename": f"logs/tcp-{logNow}-debug.log",
                "level": "DEBUG",
            },
            "regular_file": {
                "class": "logging.FileHandler",
                "formatter": "precise",
                "filename": f"logs/tcp-{logNow}.log",
                "level": "INFO",
            },
        },
        "loggers": {
            "tcp": {
                "handlers": ["regular_file", "debug_file"],
            },
        },
    }
)

logger = logging.getLogger("tcp")
logger.setLevel(logging.DEBUG)

class UDPBasedProtocol:
    udp_logger = logger.getChild("UDPBase")

    def __init__(self, *, local_addr, remote_addr) -> None:
        self.udp_logger.info(f"Opening socket {local_addr} <-> {remote_addr}")
        self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.local_addr = local_addr
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)

    def sendto(self, data) -> int:
        self.udp_logger.debug(f"Sending {len(data)} bytes {self.local_addr} -> {self.remote_addr}")
        res = self.udp_socket.sendto(data, self.remote_addr)
        self.udp_logger.debug(f"Sent {len(data)} bytes {self.local_addr} -> {self.remote_addr}")
        return res

    def recvfrom(self, n) -> bytes:
        self.udp_logger.debug(f"Receiving {n} bytes on {self.local_addr}")
        msg, addr = self.udp_socket.recvfrom(n)
        self.udp_logger.debug(f"Received {len(msg)} bytes {addr} -> {self.local_addr}")
        return msg

    def close(self) -> None:
        self.udp_logger.info(f"Closing socket {self.local_addr} <-> {self.remote_addr}")
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
    
    def __iter__(self):
        return iter((self.typ, self.start, self.end, self.seq))
    
    def __str__(self) -> str:
        return f"({self.typ}, start={self.start}, end={self.end}, seq={self.seq})"

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
    PACKET_SIZE = PacketMeta.META_SIZE + SEGMENT_SIZE

    meta: PacketMeta
    segment: bytes

    def __init__(self, meta: PacketMeta, segment: bytes = bytes()) -> None:
        if meta.typ == PacketType.DATA:
            assert len(segment) == self.SEGMENT_SIZE
        else: 
            assert len(segment) == 0
            segment = bytes(self.SEGMENT_SIZE)
        self.meta = meta
        self.segment = segment

    def __iter__(self):
        return iter((self.meta, self.segment))

class PacketProtocol:
    DEFAULT_DELAY_US = 2000
    SYN_TIMEOUT = 0.1
    FIN_TIMEOUT = 0.1
    STEP = 0.001

    logger = logger.getChild("Proto")
    hooks: list[Callable[[Packet], None]] = []

    udp: UDPBasedProtocol

    def __init__(self, udp: UDPBasedProtocol) -> None:
        self.udp = udp
        self.logger.info(f"Initialized protocol {udp.local_addr} -> {udp.remote_addr}")
    
    def receive_packet(self) -> Packet:
        packet_bytes = self.udp.recvfrom(Packet.PACKET_SIZE)
        packet_meta = bytes_to_meta(packet_bytes[:PacketMeta.META_SIZE])
        segment_bytes = bytes()
        if packet_meta.typ == PacketType.DATA:
            segment_bytes = packet_bytes[PacketMeta.META_SIZE:]
        packet = Packet(packet_meta, segment_bytes)
        self.logger.debug(f"Received packet {packet.meta} with length {len(segment_bytes)}")
        return packet
    
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
    DATA_WAIT_US = 10**6
    ESTABLISHED_WAIT_US = 3*10**6
    FIN_WAIT_US = 10**6
    ACK_WAIT_US = 10**6

    protocol: PacketProtocol
    state = State.SYN_WAIT
    buf = bytes()
    buf_ptr = 0
    seq_start = -1
    last_seq: int
    wait_start = datetime.now()
    first_unreceived: int
    data_available: bool = False
    logger = logger.getChild("Reader")

    def __init__(self, protocol: PacketProtocol) -> None:
        self.protocol = protocol
    
    def valid_seq(self, seq: int) -> bool:
        SEQ_TOLERANCE = 10000
        return in_seq_segment(seq, self.seq_start, (self.last_seq + SEQ_TOLERANCE) % 2**32)

    def handle_input(self, input: Packet | None) -> None:
        self.logger.debug(f"Handling input {input.meta if input else None} from {self.state}, seq={self.seq_start}")
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
            self.first_unreceived = 0
            self.state = self.State.ACK_WAIT
        elif self.state == self.State.ACK_WAIT:
            if not input or input.meta.typ != PacketType.ACK or input.meta.seq != self.seq_start:
                if (now - self.wait_start).microseconds > self.DATA_WAIT_US:
                    self.state = self.State.SYN_WAIT
                return 
            self.wait_start = now
            self.state = self.State.ESTABLISHED
        elif self.state == self.State.ESTABLISHED:
            if not input or \
               (not (input.meta.typ == PacketType.DATA and self.valid_seq(input.meta.seq)) and \
                not (input.meta.typ == PacketType.FIN and input.meta.seq == self.seq_start)):
                if (now - self.wait_start).microseconds > self.DATA_WAIT_US:
                    self.state = self.State.SYN_WAIT
                return
            self.wait_start = now
            if input.meta.typ == PacketType.FIN:
                self.protocol.send_packet(Packet(PacketMeta(PacketType.FIN, 0, 0, self.seq_start)))
                self.state = self.State.FIN_WAIT
                return
            if input.meta.start > self.first_unreceived:
                return
            if self.first_unreceived < input.meta.end:
                self.logger.debug(f"Received {input.meta.end - self.first_unreceived} new bytes")
                self.buf += input.segment[self.first_unreceived-input.meta.start:input.meta.end][::]
                self.first_unreceived = input.meta.end
            self.protocol.send_packet(Packet(PacketMeta(PacketType.ACK, input.meta.start, input.meta.end, input.meta.seq)))
        elif self.state == self.State.FIN_WAIT:
            if not input or not (input.meta.typ == PacketType.ACK and input.meta.seq == self.seq_start):
                if (now - self.wait_start).microseconds > self.ACK_WAIT_US:
                    self.state = self.State.ESTABLISHED
                return
            self.wait_start = now
            self.data_available = True
            self.state = self.State.SYN_WAIT

    def do_read(self, n: int) -> bytes:
        self.logger.info(f"Doing read of {n} bytes on {self.protocol.udp.local_addr}")
        while not self.data_available or self.buf_ptr + n > len(self.buf):
            sleep(PacketProtocol.STEP)
        self.data_available = False
        self.logger.info(f"Done read of {n} bytes on {self.protocol.udp.local_addr}") 
        res = self.buf[self.buf_ptr:self.buf_ptr + n][::]
        self.buf_ptr += n
        return res


class TCPWriter:
    class State(Enum):
        DEFAULT = 00
        INIT = 10
        SYNACK_WAIT = 20
        ESTABLISHED = 30
        FIN_WAIT = 40
        FINISHED = 50
    
    SYNACK_WAIT_US = 10**6
    ACK_WAIT_US = 5*10**6
    FIN_WAIT_US = 10**6
    
    state: State = State.DEFAULT
    buf: bytes = bytes()
    wait_start = datetime.now()
    seq_start = -1
    cur_seq: int
    first_unack: int
    cur_delay_us: int = PacketProtocol.DEFAULT_DELAY_US
    packet_sent: dict[int, datetime]
    protocol: PacketProtocol
    logger = logger.getChild("Writer")

    def __init__(self, protocol: PacketProtocol) -> None:
        self.protocol = protocol

    def valid_seq(self, seq: int) -> bool:
        return in_seq_segment(seq, self.seq_start, self.cur_seq)

    def handle_input(self, input: Packet | None) -> None:
        self.logger.debug(f"Handling input {input.meta if input else None} from {self.state}, seq={self.seq_start}")
        now = datetime.now()
        if self.state == self.State.DEFAULT:
            pass
        elif self.state == self.State.INIT:
            self.wait_start = now
            self.seq_start = randint(0, 2**32 - 1)
            self.protocol.send_packet(Packet(PacketMeta(PacketType.SYN, 0, 0, self.seq_start)))
            self.state = self.State.SYNACK_WAIT
        elif self.state == self.State.SYNACK_WAIT:
            if input is None or (input.meta.typ != PacketType.SYNACK):
                if (now - self.wait_start).microseconds > self.SYNACK_WAIT_US:
                    self.wait_start = now
                    self.state = self.State.INIT
                return
            self.wait_start = now
            self.protocol.send_packet(Packet(PacketMeta(PacketType.ACK, 0, 0, self.seq_start)))
            self.cur_seq = self.seq_start
            self.first_unack = 0
            self.packet_sent = dict()
            self.state = self.State.ESTABLISHED
        elif self.state == self.State.ESTABLISHED:
            if input is None or not (input.meta.typ == PacketType.ACK and self.valid_seq(input.meta.seq)):
                if (now - self.wait_start).microseconds > self.ACK_WAIT_US:
                    self.wait_start = now
                    self.state = self.State.INIT
            else:
                ack_delay = (now - self.packet_sent[input.meta.seq]).microseconds
                self.cur_delay_us = self.protocol.delay_step(self.cur_delay_us, ack_delay)
                self.wait_start = now
                if input.meta.start <= self.first_unack and input.meta.end > self.first_unack:
                    self.first_unack = input.meta.end
            if self.first_unack == len(self.buf):
                self.protocol.send_packet(Packet(PacketMeta(PacketType.FIN, 0, 0, self.seq_start)))
                self.wait_start = now
                self.state = self.State.FIN_WAIT
                return
            for start in range(self.first_unack, len(self.buf), Packet.SEGMENT_SIZE):
                cur = datetime.now()
                if (cur - now).microseconds > 2 * self.cur_delay_us:
                    break
                self.cur_seq = (self.cur_seq + 1) % 2**32
                end = min(len(self.buf), start + Packet.SEGMENT_SIZE)
                meta = PacketMeta(PacketType.DATA, start, end, self.cur_seq)
                data = self.buf[start:end][::]
                data += bytes(Packet.SEGMENT_SIZE - len(data))
                self.logger.debug(f"Sending {end - start} bytes")
                self.protocol.send_packet(Packet(meta, data))
                self.packet_sent[self.cur_seq] = cur
            cur = datetime.now()
            delta = 2 * self.cur_delay_us - (cur - now).microseconds 
            if delta > 0:
                sleep(delta / 10**6)
        elif self.state == self.State.FIN_WAIT:
            if input is None or not (input.meta.typ == PacketType.FIN and input.meta.seq == self.seq_start):
                if (now - self.wait_start).microseconds > self.FIN_WAIT_US:
                    self.state = self.State.ESTABLISHED
                return
            self.protocol.send_packet(Packet(PacketMeta(PacketType.ACK, 0, 0, self.seq_start)))
            self.state = self.State.DEFAULT

    
    def do_write(self, data: bytes) -> int:
        self.logger.info(f"Doing write of {len(data)} bytes {self.protocol.udp.local_addr} -> {self.protocol.udp.remote_addr}")
        while self.state != self.State.DEFAULT:
            sleep(PacketProtocol.STEP)
        self.buf = data[::]
        self.state = self.State.INIT
        while self.state != self.State.DEFAULT:
            sleep(PacketProtocol.STEP)
        self.logger.info(f"Done write of {len(data)} bytes {self.protocol.udp.local_addr} -> {self.protocol.udp.remote_addr}")
        return len(data)


class MyTCPProtocol(UDPBasedProtocol):
    protocol: PacketProtocol
    actor: Thread
    reader: TCPReader
    writer: TCPWriter
    logger = logger
    is_closed = False

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.logger.info(f"Opening socket {self.local_addr} <-> {self.remote_addr}")
        self.protocol = PacketProtocol(self)
        self.actor = Thread(target=self.act)
        self.reader = TCPReader(self.protocol)
        self.writer = TCPWriter(self.protocol)
        self.actor.start()
    
    def act(self) -> None:
        logger = self.logger.getChild("Actor")
        logger.info(f"Acting started")
        reader_prev_state = self.reader.state
        writer_prev_state = self.writer.state 
        logger.info(f"Reader state {reader_prev_state}")
        logger.info(f"Writer state {writer_prev_state}")
        while not self.is_closed:
            packet = self.protocol.get_one_packet(timeout=PacketProtocol.STEP)
            self.reader.handle_input(packet)
            if self.reader.state != reader_prev_state:
                logger.info(f"Reader changed state {reader_prev_state} -> {self.reader.state}")
                reader_prev_state = self.reader.state
            self.writer.handle_input(packet)
            if self.writer.state != writer_prev_state:
                logger.info(f"Writer changed state {writer_prev_state} -> {self.writer.state}")
                writer_prev_state = self.writer.state
        logger.info(f"Acting stopped")

    def send(self, data: bytes) -> int:
        self.logger.info(f"Sending {len(data)} bytes {self.local_addr} -> {self.remote_addr}")
        return self.writer.do_write(data)

    def recv(self, n: int) -> bytes:
        self.logger.info(f"Receiving {n} bytes on {self.local_addr}")
        return self.reader.do_read(n)
    
    def close(self):
        self.logger.info(f"Closing socket {self.local_addr} <-> {self.remote_addr}")
        self.is_closed = True
        self.actor.join()
        super().close()

