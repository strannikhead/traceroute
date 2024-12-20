import os, sys, argparse, time
import socket, struct
from collections import defaultdict


class IPHeader:
    def __init__(self, version, tos, total_length, ip_id, flags, ttl, protocol, checksum, source_ip, dest_ip):
        self.version = version
        self.tos = tos
        self.total_length = total_length
        self.id = ip_id
        self.flags = flags
        self.ttl = ttl
        self.protocol = protocol
        self.checksum = checksum
        self.source_ip = source_ip
        self.dest_ip = dest_ip


class ICMPHeader:
    def __init__(self, icmp_type, code, checksum, identifier, sequence):
        self.type = icmp_type
        self.code = code
        self.checksum = checksum
        self.id = identifier
        self.sequence = sequence


class Traceroute:
    def __init__(self, destination, packet_count_bytes, max_hops, timeout, interval, debug_mode):
        self.destination = destination
        self.packet_count_bytes = packet_count_bytes
        self.max_hops = max_hops
        self.timeout = timeout
        self.interval = interval
        self.debug_mode = debug_mode

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as e:
            print(e)

        self.count_of_packets = 3

        # region ICMP_codes
        self.ECHO = 8
        self.ECHO_REPLY = 0
        self.ID = os.getpid() & 0xffff
        self.response_codes = self.parse_types('icmp_response_codes.txt')
        # endregion

    def traceroute(self):
        try:
            self.try_find_host()
        except socket.gaierror:
            print(f'traceroute: unknown host {self.destination}')
            return

        icmp_header = None
        prev_server = None
        for ttl in range(1, self.max_hops + 1):
            seq = 0
            try:
                self.sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                for _ in range(self.count_of_packets):
                    self.sock.settimeout(self.timeout)
                    seq += 1

                    start_time = self.send_packet(seq)
                    if not start_time:
                        continue
                    packet = self.parse_reply(ttl, seq)
                    end_time = time.time()

                    ip_header = IPHeader(*struct.unpack("!BBHHHBBHII", packet[:20])) if packet else None
                    icmp_header = ICMPHeader(*struct.unpack("!BBHHH", packet[20:28])) if packet else None
                    delay_in_secs = end_time - start_time
                    delay = (end_time - start_time) * 1000

                    if packet:
                        ip = socket.inet_ntoa(struct.pack('!I', ip_header.source_ip))
                        try:
                            server_address = socket.gethostbyaddr(ip)[0]
                        except socket.herror:
                            server_address = ip
                        if prev_server != server_address:
                            if delay_in_secs < self.interval:
                                time.sleep(self.interval - delay_in_secs)
                            icmp_info = self.response_codes[icmp_header.type] if self.debug_mode else ''
                            print(f'{ttl if seq == 1 else ""}'
                                  f'{(3 - len(str(ttl))) * " "} '
                                  f'{server_address} ({ip})  '
                                  f'{round(delay, 3)}ms',
                                  icmp_info)
                            prev_server = server_address
                        if seq == self.count_of_packets:
                            prev_server = None
                    else:
                        if delay_in_secs < self.interval:
                            print(delay_in_secs, self.interval)
                            time.sleep(self.interval - delay_in_secs)


            except socket.error as e:
                print(e)
                break
            except KeyboardInterrupt:
                break

            if icmp_header and icmp_header.type == self.ECHO_REPLY:
                self.sock.close()
                break

    def try_find_host(self):
        destination_ip = socket.gethostbyname(self.destination)
        print(
            f'traceroute to {self.destination} ({destination_ip}), {self.max_hops} hops max, {self.packet_count_bytes} byte packets')

    # region icmp_packets
    def send_packet(self, seq):
        packet = self.craft_icmp(seq)
        send_time = time.time()
        try:
            self.sock.sendto(packet, (self.destination, 1))
        except socket.error as e:
            print(e)
            return
        return send_time

    def craft_icmp(self, seq):
        header = struct.pack("!BBHHH", self.ECHO, 0, 0, self.ID, seq)
        payload = bytes([0] * self.packet_count_bytes)
        checksum = self.checksum(header + payload)
        header = struct.pack("!BBHHH", self.ECHO, 0, checksum, self.ID, seq)
        packet = header + payload
        return packet

    @staticmethod
    def checksum(packet):
        count_to = (len(packet) // 2) * 2
        count = 0
        control_sum = 0
        while count < count_to:
            if sys.byteorder == "little":
                low_byte = packet[count]
                high_byte = packet[count + 1]
            else:
                low_byte = packet[count + 1]
                high_byte = packet[count]
            control_sum = control_sum + (high_byte * 256 + low_byte)
            count += 2
        if count_to < len(packet):
            control_sum += packet[count]
        control_sum = (control_sum >> 16) + (control_sum & 0xffff)
        control_sum += (control_sum >> 16)
        answer = socket.htons(~control_sum & 0xffff)
        return answer

    def parse_reply(self, ttl, seq):
        try:
            packet, address = self.sock.recvfrom(1500)

            self.sock.settimeout(None)
            return packet
        except socket.timeout:
            self.sock.settimeout(None)
            if seq == 1:
                print(f'{ttl}{(3 - len(str(ttl))) * " "} ', end='')
            print('* ', end='', flush=True)
            if seq == self.count_of_packets:
                print()
            return None

    # endregion end

    @staticmethod
    def parse_types(file: str) -> defaultdict[int: str]:
        types = defaultdict(lambda: 'reserved code or not existed')
        with open(file, 'r') as f:
            for line in f:
                split_data = line.strip().split()
                types[int(split_data[0])] = ' '.join(split_data[1:])
        return types


def parse_args():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('destination')
    arg_parser.add_argument('-b', '--bytes', nargs='?', default=40, type=int)
    arg_parser.add_argument('-m', '--max_hops', default=64, type=int)
    arg_parser.add_argument('-t', '--timeout', default=2, type=float)
    arg_parser.add_argument('-i', '--interval', default=0, type=float)
    arg_parser.add_argument('-d', '--debug_mode', action='store_true')
    return arg_parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    t = Traceroute(args.destination,
                   args.bytes,
                   args.max_hops,
                   args.timeout,
                   args.interval,
                   args.debug_mode)
    t.traceroute()
