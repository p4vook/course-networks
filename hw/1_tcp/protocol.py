import socket
import datetime
import select

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


def convert_to_bytes(num: int, byte_len: int):
    return bytes([(num >> (i * 8)) & 0xFF for i in range(byte_len)])

def convert_from_bytes(bytearray: bytes):
    return sum([byte << (i * 8) for (i, byte) in enumerate(bytearray)])

class MyTCPProtocol(UDPBasedProtocol):
    CHUNK_SIZE = 4000
    DEFAULT_DELAY_US = 1000

    class PacketMeta:
        NUM_SIZE = 8
        META_SIZE = 3 * NUM_SIZE

        start: int
        end: int
        pid: int
        
        def __init__(self, start: int, end: int, pid: int):
            self.start = start
            self.end = end
            self.pid = pid

        @classmethod
        def from_bytes(self, packet_bytes: bytes):
            start = convert_from_bytes(packet_bytes[:self.NUM_SIZE])
            end = convert_from_bytes(packet_bytes[self.NUM_SIZE:2*self.NUM_SIZE])
            pid = convert_from_bytes(packet_bytes[2*self.NUM_SIZE:self.META_SIZE])
            return self(start, end, pid)

        def to_bytes(self):
            return convert_to_bytes(self.start, self.NUM_SIZE) + \
                   convert_to_bytes(self.end, self.NUM_SIZE) + \
                   convert_to_bytes(self.pid, self.NUM_SIZE)

    PACKET_SIZE = CHUNK_SIZE + PacketMeta.META_SIZE

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def send_acknowledge(self, packet_meta: PacketMeta):
        return self.sendto(packet_meta.to_bytes())

    def get_acknowledge(self) -> PacketMeta:
        return self.PacketMeta.from_bytes(self.recvfrom(self.PacketMeta.META_SIZE))

    def send(self, data: bytes) -> int:
        n = len(data)
        print(f"============== SENDING {n} BYTES ==============", flush=True)
        data += bytes(self.CHUNK_SIZE)
        packet_sent_time: dict[int, datetime.datetime] = dict()
        current_id = 0
        first_unack = 0
        current_delay_us = self.DEFAULT_DELAY_US
        ack_meta = self.PacketMeta(0, 0, -1)
        while first_unack < n:
            iteration_start = datetime.datetime.now()
            for packet_start in range(first_unack, len(data) - self.CHUNK_SIZE, self.CHUNK_SIZE):
                now = datetime.datetime.now()
                if (now - iteration_start).microseconds > 2 * current_delay_us:
                    break
                packet_end = packet_start + self.CHUNK_SIZE
                current_id += 1
                meta = self.PacketMeta(packet_start, packet_end, current_id)
                packet_bytes = meta.to_bytes()
                packet_bytes += data[meta.start:meta.end]
                assert len(packet_bytes) == self.PACKET_SIZE
                print(f"Sending ({meta.start}, {meta.end}, {meta.pid})", flush=True)
                self.sendto(packet_bytes)
                packet_sent_time[meta.pid] = now
                res = select.select([self.udp_socket], [], [], 0.)
                if not res:
                    print("No meta available :(", flush=True)
                else:
                    ack_meta = self.get_acknowledge()
                    recvd = datetime.datetime.now()
                    delta_us = (recvd - packet_sent_time[ack_meta.pid]).microseconds
                    print(f"Received ack ({ack_meta.start}, {ack_meta.end}, {ack_meta.pid}), delta {delta_us}", flush=True)
                    current_delay_us = (current_delay_us + delta_us) // 2
                    if ack_meta.start <= first_unack and ack_meta.end > first_unack:
                        first_unack = ack_meta.end
                print(f"First unack {first_unack}, delay {current_delay_us}", flush=True)
        while ack_meta.pid != 0:
            ack_meta = self.get_acknowledge()
        return n

    def recv(self, n: int) -> bytes:
        res = bytes()
        first_unreceived = 0
        while first_unreceived < n:
            packet_bytes = self.recvfrom(self.PACKET_SIZE)
            meta = self.PacketMeta.from_bytes(packet_bytes)
            print(f"Received packet ({meta.start}, {meta.end}, {meta.pid})!", flush=True)
            if meta.start > first_unreceived:
                continue
            if first_unreceived < meta.end:
                segment_start = self.PacketMeta.META_SIZE + (first_unreceived - meta.start)
                segment_end = self.PacketMeta.META_SIZE + meta.end
                assert segment_start < segment_end
                res += packet_bytes[segment_start:segment_end]
                first_unreceived = len(res)
            self.send_acknowledge(meta)
        self.send_acknowledge(self.PacketMeta(0, 0, 0))
        return res[:n]
    
    def close(self):
        super().close()

