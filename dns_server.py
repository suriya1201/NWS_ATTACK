from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, QTYPE, A
from dnslib.server import DNSServer, DNSHandler, BaseResolver
import logging

# Set up basic logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RedirectResolver(BaseResolver):
    """
    Custom DNS resolver class that redirects DNS queries to a specified IP address.
    
    Attributes:
        redirect_ip (str): The IP address to which DNS queries should be redirected.
    """
    def __init__(self, redirect_ip):
        """
        Initializes the RedirectResolver with a target IP address for redirection.
        
        Args:
            redirect_ip (str): The IP address to which DNS queries will be redirected.
        """
        self.redirect_ip = redirect_ip

    def resolve(self, request, handler):
        """
        Overrides the resolve method to modify DNS responses.
        
        Modifies the response to redirect DNS queries for A records to a specified IP address.
        
        Args:
            request (DNSRequest): The incoming DNS request.
            handler (DNSHandler): The DNS handler object.
            
        Returns:
            DNSResponse: The modified DNS response.
        """
        reply = request.reply()
        qname = request.q.qname
        qtype = request.q.qtype

        logger.info(f"Query: {qname} Type: {QTYPE[qtype]}")

        if qtype == QTYPE.A:  # If the query is for an A record
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(self.redirect_ip), ttl=60))
        return reply

if __name__ == '__main__':
    """
    Main entry point for the DNS server script.
    Initializes and starts the DNS server, redirecting all DNS queries to a specified IP address.
    """
    redirect_ip = "192.168.1.19"  # Replace with your IP address
    
    resolver = RedirectResolver(redirect_ip)
    dns_server = DNSServer(resolver, port=53, address="0.0.0.0")
    
    logger.info(f"Starting DNS server on 0.0.0.0:53, redirecting all queries to {redirect_ip}")
    dns_server.start_thread()
    
    # Keep the main thread running until interrupted
    try:
        while True:
            pass
    except KeyboardInterrupt:
        dns_server.stop()
        logger.info("DNS server stopped")