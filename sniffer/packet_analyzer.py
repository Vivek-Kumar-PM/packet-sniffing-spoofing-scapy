# ============================================================
# FILE: sniffer/packet_analyzer.py
# PURPOSE: Reads and displays detailed information from each
#          captured packet including IP, TCP, UDP, ICMP layers
# WHY NEEDED: Separated from sniffer.py because capturing packets
#             and analyzing packets are two different operations.
#             This follows Single Responsibility Principle.
#             A packet sniffer should only capture — the analyzer
#             should only read and display packet contents.
#             This also makes it easier to modify display format
#             without touching the capture logic.
# ============================================================

from scapy.all import IP, TCP, UDP, ICMP, Raw
# IP    → Internet Protocol layer (source/dest IP, TTL)
# TCP   → Transmission Control Protocol (ports, flags, connection state)
# UDP   → User Datagram Protocol (ports, lightweight no-connection protocol)
# ICMP  → Internet Control Message Protocol (ping, network diagnostics)
# Raw   → The actual payload/data carried inside the packet

from utils.helpers import log_packet, print_separator
# Import our shared utilities for consistent formatting

def analyze_packet(packet):
    # --------------------------------------------------------
    # This function is called automatically by sniff() for
    # EVERY packet that is captured on the network interface
    # It checks which layers exist in the packet and displays
    # the relevant fields from each layer
    # --------------------------------------------------------
    
    print_separator()
    # Visual divider so each packet is clearly separated in output

    # ---- CHECK FOR IP LAYER ----
    if IP in packet:
        # "IP in packet" checks if this packet has an IP layer
        # Almost all internet traffic has an IP layer
        
        src_ip = packet[IP].src    
        # Source IP = WHERE the packet came from
        # In spoofing attacks, this is the field that gets FAKED
        
        dst_ip = packet[IP].dst    
        # Destination IP = WHERE the packet is going
        
        ttl = packet[IP].ttl       
        # TTL = Time To Live
        # Number of hops (routers) packet can pass through before dying
        # Low TTL can indicate spoofed or distant packets
        
        proto = packet[IP].proto   
        # Protocol number: 6=TCP, 17=UDP, 1=ICMP
        # Tells us what type of traffic this is

        log_packet("IP Packet Detected")
        print(f"  Source IP      : {src_ip}")
        print(f"  Destination IP : {dst_ip}")
        print(f"  TTL            : {ttl}")
        print(f"  Protocol       : {proto}")

    # ---- CHECK FOR TCP LAYER ----
    if TCP in packet:
        # TCP is used by HTTP, HTTPS, SSH, FTP and most web traffic
        # Checking TCP in packet verifies this is a TCP segment
        
        src_port = packet[TCP].sport  
        # Source port = port number on the SENDER side
        
        dst_port = packet[TCP].dport  
        # Destination port = port on RECEIVER side
        # Port 80=HTTP, 443=HTTPS, 22=SSH, 21=FTP
        
        flags = packet[TCP].flags     
        # TCP Flags show the STATE of the connection:
        # S  = SYN  (starting connection)
        # A  = ACK  (acknowledging)
        # F  = FIN  (closing connection)
        # R  = RST  (reset/abort)
        # SA = SYN-ACK (server responding to connection)

        print(f"  Protocol Type  : TCP")
        print(f"  Source Port    : {src_port}")
        print(f"  Dest Port      : {dst_port}")
        print(f"  TCP Flags      : {flags}")

    # ---- CHECK FOR UDP LAYER ----
    elif UDP in packet:
        # UDP is used by DNS, video streaming, gaming
        # Unlike TCP, UDP has no connection — just sends and forgets
        
        src_port = packet[UDP].sport  # Sender port
        dst_port = packet[UDP].dport  # Receiver port

        print(f"  Protocol Type  : UDP")
        print(f"  Source Port    : {src_port}")
        print(f"  Dest Port      : {dst_port}")

    # ---- CHECK FOR ICMP LAYER ----
    elif ICMP in packet:
        # ICMP is used for ping and network diagnostics
        # Our icmp_spoofer.py sends fake ICMP packets
        # Here we can see and verify those fake packets
        
        icmp_type = packet[ICMP].type  
        # Type 8 = Echo Request (ping sent)
        # Type 0 = Echo Reply (ping response)
        
        icmp_code = packet[ICMP].code  
        # Code gives more detail about the ICMP message type

        print(f"  Protocol Type  : ICMP")
        print(f"  ICMP Type      : {icmp_type}")
        print(f"  ICMP Code      : {icmp_code}")

    # ---- CHECK FOR RAW PAYLOAD ----
    if Raw in packet:
        # Raw layer = the actual data/payload inside the packet
        # This shows what information is being transmitted
        # Demonstrates why unencrypted traffic is dangerous —
        # an attacker can read the actual content
        
        payload = packet[Raw].load
        print(f"  Payload        : {payload[:50]}")  
        # Only show first 50 bytes to keep output readable
        # In real attacks, attacker reads the full payload