# ============================================================
# FILE: main.py
# PURPOSE: Single entry point that runs the COMPLETE demonstration
#          automatically — sniffing, spoofing, and Wireshark
#          validation guidance all in one flow.
# WHY NEEDED: Orchestrates all modules together into one clean
#             automated pipeline. Professor and team can run
#             ONE file and see the entire project demonstrated.
#             Also provides Wireshark filter guidance at each
#             step so the Wireshark team member knows exactly
#             what to look for and screenshot for the report.
# ============================================================

import time
# time module used for pauses between operations
# Gives Wireshark time to capture packets before next step

from sniffer.packet_sniffer import start_sniffing
# Import sniffing function from our sniffer module

from spoofer.ip_spoofer import send_spoofed_syn, send_spoofed_fin
# Import both TCP spoofing functions

from spoofer.icmp_spoofer import send_fake_ping, send_icmp_flood
# Import both ICMP spoofing functions

from utils.helpers import print_separator, log_packet
# Import shared utilities for consistent output formatting

# ============================================================
# CONFIGURATION — Change these values for your VM network
# ============================================================
ATTACKER_INTERFACE = "enp0s3"       
# Network interface to sniff on (run 'ip addr show' to confirm)

TARGET_IP = "10.0.2.1"       
# IP address of VM2 (Victim machine in your VirtualBox network)

FAKE_SRC_IP = "10.0.2.99"    
# Fake IP we will forge in spoofed packets
# This IP does not belong to any real machine

TARGET_PORT = 80                  
# Port we target in TCP spoofing (80 = HTTP)

SNIFF_COUNT = 10                  
# Number of packets to capture during sniffing demo
# Keep low for quick demonstration


def print_wireshark_guide():
    # --------------------------------------------------------
    # Prints Wireshark filter guide for the team member
    # responsible for traffic validation and screenshots
    # This directly supports the Wireshark responsibilities
    # mentioned in the project requirements
    # --------------------------------------------------------
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║           WIRESHARK VALIDATION GUIDE                    ║
    ╠══════════════════════════════════════════════════════════╣
    ║  Open Wireshark → Select interface: enp0s3                ║
    ║                                                          ║
    ║  Filters to use at each step:                           ║
    ║                                                          ║
    ║  Step 1 - Packet Sniffing:                              ║
    ║    → Filter: ip                                          ║
    ║    → Look for: IP packets with src/dst addresses        ║
    ║    → Screenshot: Packet list + packet details panel     ║
    ║                                                          ║
    ║  Step 2 - SYN Spoofing:                                 ║
    ║    → Filter: tcp.flags.syn==1                           ║
    ║    → Look for: SYN packets from 192.168.100.99          ║
    ║    → Screenshot: Source IP showing fake address         ║
    ║                                                          ║
    ║  Step 3 - FIN Spoofing:                                 ║
    ║    → Filter: tcp.flags.fin==1                           ║
    ║    → Look for: FIN packets from fake IP                 ║
    ║    → Screenshot: TCP flags column                       ║
    ║                                                          ║
    ║  Step 4 - ICMP Fake Ping:                               ║
    ║    → Filter: icmp                                        ║
    ║    → Look for: Echo request from fake IP                ║
    ║    → Screenshot: ICMP packet details                    ║
    ║                                                          ║
    ║  Step 5 - ICMP Flood:                                   ║
    ║    → Filter: icmp && ip.src==192.168.100.99             ║
    ║    → Look for: Multiple ICMP packets rapidly            ║
    ║    → Screenshot: Flood of packets in packet list        ║
    ╚══════════════════════════════════════════════════════════╝
    """)


def run_full_demonstration():
    # --------------------------------------------------------
    # MAIN FUNCTION — Runs complete project demonstration
    # All steps run automatically in sequence with pauses
    # so Wireshark team member can capture screenshots
    # --------------------------------------------------------

    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║     Packet Sniffing & Spoofing — Full Demonstration     ║
    ║          Lab of Computer Security Project               ║
    ╚══════════════════════════════════════════════════════════╝
    """)

    # Show Wireshark guide FIRST so team member sets up filters
    print_wireshark_guide()

    input("\n[*] Press ENTER when Wireshark is open and ready...\n")
    # Pauses execution until Wireshark is confirmed open
    # Ensures no packets are missed during demonstration

    # ========================================================
    # STEP 1: PACKET SNIFFING DEMONSTRATION
    # ========================================================
    print_separator()
    log_packet("STEP 1: Starting Packet Sniffing Demonstration")
    print(f"  Interface : {ATTACKER_INTERFACE}")
    print(f"  Capturing : {SNIFF_COUNT} packets")
    print(f"  Wireshark : Filter with 'ip' to see all packets")
    print()

    input("[*] Press ENTER to start sniffing...\n")
    start_sniffing(interface=ATTACKER_INTERFACE, packet_count=SNIFF_COUNT)
    # Captures SNIFF_COUNT packets and displays their details
    # Wireshark running simultaneously shows the same traffic

    print("\n[✓] Step 1 Complete — Take Wireshark screenshot now!")
    input("[*] Press ENTER to continue to spoofing...\n")

    # ========================================================
    # STEP 2: IP SPOOFING — SYN PACKET
    # ========================================================
    print_separator()
    log_packet("STEP 2: IP Spoofing — SYN Packet")
    print(f"  Fake Source IP : {FAKE_SRC_IP}")
    print(f"  Target IP      : {TARGET_IP}")
    print(f"  Wireshark      : Filter with 'tcp.flags.syn==1'")
    print()

    input("[*] Press ENTER to send spoofed SYN packet...\n")
    send_spoofed_syn(FAKE_SRC_IP, TARGET_IP, TARGET_PORT)
    # Sends ONE packet with forged source IP
    # Wireshark will show the packet appearing from FAKE_SRC_IP

    time.sleep(1)
    # Small pause so Wireshark has time to display the packet
    # before moving to next step

    print("\n[✓] Step 2 Complete — Screenshot the fake source IP!")
    input("[*] Press ENTER to continue...\n")

    # ========================================================
    # STEP 3: IP SPOOFING — FIN PACKET
    # ========================================================
    print_separator()
    log_packet("STEP 3: IP Spoofing — FIN Packet")
    print(f"  Wireshark : Filter with 'tcp.flags.fin==1'")
    print()

    input("[*] Press ENTER to send spoofed FIN packet...\n")
    send_spoofed_fin(FAKE_SRC_IP, TARGET_IP, TARGET_PORT)
    # Sends FIN packet with forged source — simulates
    # forceful connection termination from fake identity

    time.sleep(1)

    print("\n[✓] Step 3 Complete — Screenshot the FIN flag!")
    input("[*] Press ENTER to continue...\n")

    # ========================================================
    # STEP 4: ICMP SPOOFING — FAKE PING
    # ========================================================
    print_separator()
    log_packet("STEP 4: ICMP Spoofing — Fake Ping")
    print(f"  Wireshark : Filter with 'icmp'")
    print()

    input("[*] Press ENTER to send fake ICMP ping...\n")
    send_fake_ping(FAKE_SRC_IP, TARGET_IP)
    # Sends a ping that appears to come from FAKE_SRC_IP
    # Target replies to fake IP — demonstrates identity forgery

    time.sleep(1)

    print("\n[✓] Step 4 Complete — Screenshot the ICMP packet!")
    input("[*] Press ENTER to continue...\n")

    # ========================================================
    # STEP 5: ICMP FLOOD DEMONSTRATION
    # ========================================================
    print_separator()
    log_packet("STEP 5: ICMP Flood — Basic DoS Demonstration")
    print(f"  Wireshark : Filter with 'icmp && ip.src=={FAKE_SRC_IP}'")
    print(f"  Sending   : 10 packets (safe demo amount)")
    print()

    input("[*] Press ENTER to start ICMP flood...\n")
    send_icmp_flood(FAKE_SRC_IP, TARGET_IP, count=10)
    # Sends 10 rapid ICMP packets from fake source
    # Wireshark will show burst of packets — demonstrates
    # how flood attacks overwhelm a target

    time.sleep(1)

    # ========================================================
    # FINAL SUMMARY
    # ========================================================
    print_separator()
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║              DEMONSTRATION COMPLETE ✓                   ║
    ╠══════════════════════════════════════════════════════════╣
    ║  Wireshark Evidence Checklist for Report:               ║
    ║                                                          ║
    ║  □ Screenshot 1: Sniffed packets (Step 1)               ║
    ║  □ Screenshot 2: Spoofed SYN packet (Step 2)            ║
    ║  □ Screenshot 3: Spoofed FIN packet (Step 3)            ║
    ║  □ Screenshot 4: Fake ICMP ping (Step 4)                ║
    ║  □ Screenshot 5: ICMP flood burst (Step 5)              ║
    ║                                                          ║
    ║  Save .pcap file: File → Save As → demo_capture.pcap    ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    log_packet("All demonstrations completed successfully.")


# ============================================================
# ENTRY POINT
# Python runs this block when you execute: sudo python3 main.py
# The if __name__ == "__main__" check ensures this only runs
# when executed directly, not when imported by another file
# ============================================================
if __name__ == "__main__":
    run_full_demonstration()