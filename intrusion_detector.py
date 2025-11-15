import socket
import struct
from collections import defaultdict
import datetime


def sniff_packets():
    """Sniff incoming packets and detect potential port scans based on SYN packets."""
    # Create a raw socket to capture all packets
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    src_count = defaultdict(int)
    while True:
        raw_data, addr = conn.recvfrom(65536)
        # Unpack Ethernet frame (destination MAC, source MAC, protocol)
        dest_mac, src_mac, proto = struct.unpack('!6s6sH', raw_data[:14])
        if proto != 0x0800:
            # Not IPv4
            continue
        # Unpack IP header
        ip_header = raw_data[14:34]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        src_ip = socket.inet_ntoa(iph[8])
        protocol = iph[6]
        # Check for TCP protocol (protocol number 6)
        if protocol == 6:
            tcp_header = raw_data[34:54]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            src_port = tcph[0]
            flags = tcph[5]
            syn_flag = flags & 0x02
            if syn_flag:
                src_count[src_ip] += 1
                if src_count[src_ip] > 100:
                    print(f"[{datetime.datetime.now()}] Possible port scan from {src_ip}, SYN packets count={src_count[src_ip]}")
                    # reset count to avoid spamming
                    src_count[src_ip] = 0


if __name__ == '__main__':
    try:
        sniff_packets()
    except KeyboardInterrupt:
        print("Stopping packet sniffer.")
