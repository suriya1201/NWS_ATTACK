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
        self.host_name = self.construct_host_name()
        self.param_req_list = [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]  # Option codes for Subnet Mask, Router, and Domain Name Server
        self.vendor_class_id = "MSFT 5.0"  # vendor class ID
        hardware_type = '01'
        self.client_id = hardware_type + (self.mac).replace(':', '')

    def get_random_mac(self):
        oui_prefix = "d0:5f:64:"  
        mac_suffix = "%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
        return oui_prefix + mac_suffix
    
    def construct_host_name(self):
        # Convert the MAC address to a lowercase string
        mac_str = self.mac.lower()
        # Extract the last three octets and join them with dots
        mac_last_three_octets = ":".join(mac_str.split(":")[3:])
        # Construct the hostname using the extracted octets
        return str(f"MyPC-{mac_last_three_octets}")
    
    def send_dhcp_discover(self):
        
        # Define the Parameter Request List
        discover = (
            Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=[mac2str(self.mac)], xid=self.transaction_id) /
            DHCP(options=[("message-type", "discover"),
                           ("client_id", bytes.fromhex(self.client_id)),
                           ("hostname", self.host_name),
                           ("vendor_class_id", self.vendor_class_id),
                           ("param_req_list", self.param_req_list),  # Adding the Parameter Request List
                           "end"])
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
                          ("client_id", bytes.fromhex(self.client_id)),
                          ("requested_addr", requested_ip),
                          ("server_id", server_ip),
                          ("hostname", self.host_name),
                          ("fqdn", self.host_name),  # Adding the FQDN option
                          ("vendor_class_id", self.vendor_class_id),
                          ("param_req_list", self.param_req_list),  # Adding the Parameter Request List
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
    