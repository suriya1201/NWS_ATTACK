from scapy.all import *
import random
import time

NUM_CLIENTS = 16 # Number of clients to simulate

class DHCPClient:
    def __init__(self, iface):
        self.iface = iface
        self.mac = self.get_random_mac()
        self.transaction_id = random.randint(1, 900000000)
        self.ip_address = None  # Initialize IP address attribute

    def get_random_mac(self):
        return "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))

    def send_dhcp_discover(self):
        discover = (
            Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=[mac2str(self.mac)], xid=self.transaction_id) /
            DHCP(options=[("message-type", "discover"), "end"])
        )
        sendp(discover, iface=self.iface, verbose=0)

    def handle_dhcp_offer(self, pkt):
        if DHCP in pkt and pkt[DHCP].options[0][1] == 2:
            offered_ip = pkt[BOOTP].yiaddr
            server_ip = pkt[IP].src
            self.ip_address = offered_ip  # Store the offered IP address
            self.send_dhcp_request(offered_ip, server_ip)

    def send_dhcp_request(self, requested_ip, server_ip):
        request = (
            Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=[mac2str(self.mac)], xid=self.transaction_id) /
            DHCP(options=[("message-type", "request"),
                          ("requested_addr", requested_ip),
                          ("server_id", server_ip),
                          "end"])
        )
        sendp(request, iface=self.iface, verbose=0)

    def start(self):
        self.send_dhcp_discover()

# Global list to track exhausted IP addresses
exhausted_ips = []

def handle_packet(pkt):
    if DHCP in pkt and pkt[DHCP].options[0][1] == 2:  # DHCP Offer
        client = DHCPClient(iface="Ethernet")
        client.handle_dhcp_offer(pkt)
        exhausted_ips.append(client.ip_address)  # Add the IP address to the list

def start_clients(num_clients, iface):
    for _ in range(num_clients):
        client = DHCPClient(iface)
        client.start()
        time.sleep(0.3)  # Slight delay to avoid flooding

if __name__ == "__main__":
    iface = "Ethernet"
    sniff_thread = threading.Thread(target=sniff, kwargs={"filter": "udp and (port 67 or 68)", "prn": handle_packet, "store": 0, "iface": iface})
    sniff_thread.start()

    start_clients(NUM_CLIENTS, iface)

    # Display the list of exhausted IP addresses after all clients have finished
    print("Exhausted IP Addresses:", exhausted_ips)
    