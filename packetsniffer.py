from scapy.all import *
from scapy.layers.http import HTTPRequest  # import HTTP packet
from scapy.layers.inet import IP
from colorama import init, Fore  # Color for HTTP requests
import argparse

# Makes the color for HTTP requests

init()
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET


def sniff_packets(iface=None):
    # Sniff 80 port packets with iface
    if iface:
        # port 80 for http
        sniff(filter="port 80", prn=process_packet, iface=iface, store=False)
    else:
        # sniff with default interface
        sniff(filter="port 80", prn=process_packet, store=False)


def process_packet(packet):
    # This function is executed whenever a packet is sniffed
    if packet.haslayer(HTTPRequest):
        # if this packet is an HTTP Request get the requested URL
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # get the requester's IP Address
        ip = packet[IP].src
        # get the request method
        method = packet[HTTPRequest].Method.decode()
        print(f"\n{GREEN}[+] {ip} Requested {url} with {method}{RESET}")
        if show_raw and packet.haslayer(Raw) and method == "POST":
            # If the red flag shows, it will POST the raw data
            print(f"\n{RED}[*] Some useful Raw data: {packet[Raw].load}{RESET}")


if __name__ != "__main__":
    pass
else:
    parser = argparse.ArgumentParser(description="HTTP Packet Sniffer")
    parser.add_argument("-i", "--iface")
    parser.add_argument("--show-raw", dest="show_raw", action="store_true")
    # parse arguments
    args = parser.parse_args()
    iface = args.iface
    show_raw = args.show_raw
    sniff_packets(iface)
