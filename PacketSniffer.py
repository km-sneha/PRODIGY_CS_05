from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.sendrecv import sniff
from scapy.config import conf
from scapy.interfaces import get_if_list
from colorama import Fore, Style, init

# Disable L3RawSocket and use Scapy's default socket (works with Npcap)
conf.L3socket = None

# Initialize colorama for colored output
init(autoreset=True)

def print_header():
    print(Fore.CYAN + "="*50)
    print(Fore.CYAN + "      🌐 Packet Sniffer - Ethical Use Only 🌐")
    print(Fore.CYAN + "="*50)

def analyze_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        # Convert protocol number to name
        proto_name = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }.get(protocol, 'OTHER')

        print(Fore.YELLOW + f"[+] Packet: {src_ip} ➜ {dst_ip} | Protocol: {proto_name}")

        payload = b''
        if proto_name == 'TCP' and TCP in packet:
            payload = bytes(packet[TCP].payload)
        elif proto_name == 'UDP' and UDP in packet:
            payload = bytes(packet[UDP].payload)
        elif proto_name == 'ICMP' and ICMP in packet:
            payload = bytes(packet[ICMP].payload)

        if payload:
            try:
                data = payload.decode('utf-8', errors='ignore')
                print(Fore.GREEN + f"    Payload: {data[:100]}")
            except:
                print(Fore.RED + "    [!] Cannot decode payload.")
    else:
        print(Fore.LIGHTBLACK_EX + "Non-IP packet captured.")

def start_sniffing(interface):
    print_header()
    print(Fore.MAGENTA + f"[*] Sniffing on interface: {interface}")
    try:
        sniff(filter="ip", iface=interface, prn=analyze_packet, store=False, count=10)
    except PermissionError:
        print(Fore.RED + "[!] Run the script as Administrator.")
    except Exception as e:
        print(Fore.RED + f"[!] Error: {e}")

if __name__ == "__main__":
    # Print available interfaces on your system
    print("Available interfaces on your system:\n")
    for iface in get_if_list():
        print("-", iface)

    # Ask user to input the correct network interface name
    chosen_interface = input("\nEnter your network interface name from above: ")
    start_sniffing(interface=chosen_interface)
