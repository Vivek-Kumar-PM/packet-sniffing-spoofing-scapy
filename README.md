Packet Sniffing & Spoofing Tool (Python / Scapy)

An educational network security tool that captures live traffic and crafts spoofed packets (TCP and ICMP), built and tested in an isolated virtual lab and validated with Wireshark.

Built by Vivek Kumar for the Lab of Computer Security course, Ca' Foscari University of Venice (2026).

What it does
Sniffer: captures packets on the network interface and shows their headers and payload (e.g. a readable HTTP GET request).
IP spoofer: sends packets with a forged source IP address:
TCP packets with custom flags (SYN, FIN)
ICMP echo requests (ping)
Validation: every result was verified independently in Wireshark.
Proof (Wireshark validation)
Screenshot	What it shows
Sniffer	Sniffer capturing a real HTTP request from the VM, with the payload visible
TCP SYN	Spoofed TCP SYN sent from the fake IP 10.0.2.99 instead of the VM's real IP 10.0.2.15
TCP FIN	Same spoofed packet with a different TCP flag (FIN): custom packet crafting
ICMP	Spoofed ICMP ping from the fake IP
Validation	Wireshark filter ip.src==10.0.2.99: spoofed pings with "no response found", as expected, since replies go to an address that doesn't exist

Key observation: the packets leave from the VM's real MAC address but carry a fake IP address, which demonstrates that the spoofing happens at the IP layer.

Tech stack
Python 3 with Scapy
Linux Mint virtual machine on Oracle VirtualBox (NAT network)
Wireshark for packet analysis and validation
Project structure
├── main.py            # Entry point
├── sniffer/           # Packet capture
├── spoofer/           # Spoofed packet crafting (TCP, ICMP)
├── utils/             # Shared helper functions
├── proof/             # Wireshark screenshots
├── result2.pcapng     # Raw packet capture from the lab
├── result2.txt        # Capture output
├── wireshark.txt      # Wireshark notes
├── setup.md           # Detailed setup guide
└── requirements.txt   # Python dependencies
How to run

Run inside a Linux virtual machine. Sending raw packets needs root privileges.

bash
# 1. Create and activate a virtual environment
python3 -m venv ~/scapy-env
source ~/scapy-env/bin/activate

# 2. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 3. Run (root needed for raw sockets)
sudo ~/scapy-env/bin/python main.py

Press Ctrl + C to stop. See setup.md for the full step-by-step guide.

Skills demonstrated
Network programming: packet capture and crafting with Python and Scapy
Lab setup: virtual environment with VirtualBox, Linux Mint, NAT networking and shared folders
Validation: independent verification of results in Wireshark
Documentation: technical report, setup guide and project defense
What I learned
How packets are structured layer by layer (Ethernet → IP → TCP/ICMP → payload)
Why IP spoofing works, and why responses never return to the attacker
How to verify technical claims with independent evidence, not just program output
Disclaimer

This project is for educational purposes only and was run exclusively in an isolated virtual lab. Do not use it on networks you do not own or have explicit permission to test.
