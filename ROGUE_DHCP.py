from scapy.all import *
from scapy.layers.dhcp import *
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether

# Define the DHCP server configuration
server_ip = '192.168.1.9'
subnet_mask = '255.255.255.240'
lease_time = 86400  # Lease time in seconds
Renewal_Time = 43200
rebinding_time_value = 75600
ip_pool = [ '192.168.1.2','192.168.1.3', '192.168.1.4', '192.168.1.10', '192.168.1.11', '192.168.1.20' ]  # Example IP pool
dns_server = "192.168.1.9"
offered_ips = {}
def handle_dhcp_packet(packet):
    if packet[DHCP] and packet[DHCP].options[0][1] == 1:  # DHCP Discover
        print("DHCP Discover received")
        offer_ip = ip_pool.pop(0)
        print(offer_ip)
        offered_ips[packet[Ether].src] = offer_ip
        send_dhcp_offer(packet, offer_ip)
    elif packet[DHCP] and packet[DHCP].options[0][1] == 3:  # DHCP Request
        print("DHCP Request received")
        client_mac = packet[Ether].src
        if client_mac in offered_ips:
            send_dhcp_ack(packet, offered_ips[client_mac])

def send_dhcp_offer(discover_packet, offer_ip):
    transaction_id = discover_packet[BOOTP].xid
    offer_packet = Ether(src="D0:5F:64:35:A7:3C", dst=discover_packet[Ether].src) / \
                   IP(src=server_ip, dst=offer_ip) / \
                   UDP(sport=67, dport=68) / \
                   BOOTP(op=2,xid=transaction_id, yiaddr=offer_ip, chaddr=discover_packet[Ether].chaddr) / \
                    DHCP(options=[('message-type', 'offer'),
                                 ('server_id', server_ip),
                                 ('lease_time', lease_time),
                                 ('renewal_time', Renewal_Time),
                                 ('rebinding_time', rebinding_time_value),
                                 ('subnet_mask', subnet_mask),
                                 ('name_server', dns_server),
                                 ('end')])
    sendp(offer_packet, iface="Ethernet", verbose=False)

def send_dhcp_ack(request_packet, assigned_ip):
    transaction_id = request_packet[BOOTP].xid
    ack_packet = Ether(src="D0:5F:64:35:A7:3C", dst=request_packet[Ether].src) / \
                 IP(src=server_ip, dst=assigned_ip) / \
                 UDP(sport=67, dport=68) / \
                 BOOTP(op=2,xid=transaction_id, yiaddr=assigned_ip, chaddr=request_packet[Ether].chaddr) / \
                 DHCP(options=[('message-type', 'ack'),
                               ('server_id', server_ip),
                                 ('lease_time', lease_time),
                                 ('renewal_time', Renewal_Time),
                                 ('rebinding_time', rebinding_time_value),
                                 ('subnet_mask', subnet_mask),
                                 ('name_server', dns_server),
                                 ('end')])
                            
   
    sendp(ack_packet, iface="Ethernet",verbose=False)

print("DHCP Server is running...")
sniff(filter="udp and (port 67 or 68) ", prn=handle_dhcp_packet, iface="Ethernet")
