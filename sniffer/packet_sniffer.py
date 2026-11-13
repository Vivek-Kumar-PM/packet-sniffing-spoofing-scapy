# ============================================================
# FILE: sniffer/packet_sniffer.py
# PURPOSE: Captures live network packets from a network interface
# WHY NEEDED: This is the CORE of Part 1 of the project.
#             It listens on a network interface (like eth0) and
#             intercepts every packet passing through it.
#             This demonstrates how attackers perform passive
#             reconnaissance by monitoring network traffic.
# ============================================================

from scapy.all import sniff         
# sniff() is Scapy's main packet capture function
# It listens on a network interface and captures packets in real time

from sniffer.packet_analyzer import analyze_packet  
# We import our analyzer so every captured packet is immediately analyzed
# This connects the two sniffer files together

def start_sniffing(interface="enp0s3", packet_count=20):
    # --------------------------------------------------------
    # PARAMETERS:
    #   interface    → which network card to listen on
    #                  eth0 = ethernet, wlan0 = wifi
    #   packet_count → how many packets to capture before stopping
    # --------------------------------------------------------
    
    print(f"[*] Starting packet sniffer on interface: {interface}")
    print(f"[*] Capturing {packet_count} packets...")
    print(f"[*] Open Wireshark now to validate captured traffic\n")
    # Reminder to open Wireshark alongside so traffic can be
    # visually verified and screenshots taken for the report

    sniff(
        iface=interface,        
        # iface tells Scapy WHICH network interface to listen on
        # Must match the interface name shown in: ip addr show
        
        prn=analyze_packet,     
        # prn = "process function"
        # Every time a packet is captured, it is passed to
        # analyze_packet() automatically for inspection
        
        count=packet_count,     
        # Stops sniffing after this many packets
        # Prevents infinite loop during testing
        
        store=False             
        # Do NOT store packets in memory
        # Saves RAM — important when capturing many packets
    )

    print("\n[*] Sniffing complete.")
    print("[*] Check Wireshark to compare and validate results.")
    # Prompt to cross-reference with Wireshark output
    # Wireshark should show the same packets we captured