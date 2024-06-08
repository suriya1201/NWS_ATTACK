from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, QTYPE, A
from dnslib.server import DNSServer, DNSHandler, BaseResolver
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RedirectResolver(BaseResolver):
    def __init__(self, redirect_ip):
        self.redirect_ip = redirect_ip

    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        qtype = request.q.qtype

        logger.info(f"Query: {qname} Type: {QTYPE[qtype]}")

        if qtype == QTYPE.A:  # If the query is for an A record
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(self.redirect_ip), ttl=60))
        return reply

if __name__ == '__main__':
    redirect_ip = "192.168.1.19"  # Replace with your IP address

    resolver = RedirectResolver(redirect_ip)
    dns_server = DNSServer(resolver, port=53, address="0.0.0.0")
    
    logger.info(f"Starting DNS server on 0.0.0.0:53, redirecting all queries to {redirect_ip}")
    dns_server.start_thread()

    # Keep the main thread running
    try:
        while True:
            pass
    except KeyboardInterrupt:
        dns_server.stop()
        logger.info("DNS server stopped")
