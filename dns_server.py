import socket
from dnslib import DNSRecord, QTYPE, RR, A
from dnslib.server import DNSServer, BaseResolver, DNSLogger

class ProxyResolver(BaseResolver):
    def __init__(self, upstream, spoof_map=None):
        self.upstream = upstream
        self.spoof_map = spoof_map if spoof_map else {}

    def resolve(self, request, handler):
        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]

        # Check if we need to spoof the response
        if qname in self.spoof_map and qtype in self.spoof_map[qname]:
            reply = request.reply()
            reply.add_answer(RR(qname, qtype, rdata=A(self.spoof_map[qname][qtype]), ttl=60))
            return reply

        # Proxy the request to the upstream DNS server
        upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream_sock.sendto(request.pack(), self.upstream)
        response_data, _ = upstream_sock.recvfrom(4096)
        upstream_sock.close()

        response = DNSRecord.parse(response_data)
        return response

if __name__ == "__main__":
    # Upstream DNS server (e.g., Google DNS)
    upstream_dns = ("8.8.8.8", 53)

    # Spoofing map: domain -> {qtype -> IP}
    spoof_map = {
        "example.local.": {QTYPE.A: "192.168.1.100"}
    }

    resolver = ProxyResolver(upstream_dns, spoof_map)
    logger = DNSLogger()

    # Start the DNS server
    server = DNSServer(resolver, port=53, address="localhost", logger=logger)
    server.start_thread()

    print("DNSChef-like DNS Server is running...")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        server.stop()
        print("DNS Server stopped.")
