
#-----------------------------------------------------------------------------
# A TCP dispatcher (hash based on client IP)
# Ref: http://stackoverflow.com/questions/4096061/general-question-regarding-wether-or-not-use-twisted-in-tcp-proxy-project 
#-----------------------------------------------------------------------------

from netaddr import IPAddress, IPNetwork, AddrFormatError
from twisted.application import service
from twisted.internet import reactor, defer, ssl, protocol
from twisted.internet.endpoints import serverFromString
from twisted.internet.protocol import Factory
from twisted.protocols.portforward import ProxyServer, ProxyFactory
from twisted.python import log
from proxies.adminws import make_ws


class GoodbyeProtocol(protocol.Protocol):

    def connectionMade(self, data):
        self.transport.loseConnection()


class Balancer(Factory):
    """
    `netmap` should be a sequence of tuples:
        (client_ip_network, client_port, dst_host, dst_port)

    `client_ip_network` should be a string representation of an IP network (e.g. "192.0.2.0/24").
    `client_port` may be an integer or '*' (any port matches).
    `dst_host` is the remote host.
    `dst_port` is the remote port.
    """
    debug = False

    def __init__(self, hostports, netmap=None):
        self.setHostPorts(hostports)
        self.setNetmap(netmap)

    def getHostPorts(self):
        return list(self._hostports)

    def setHostPorts(self, value):
        if value is None:
            self._hostports = None
            self.factories = None
            return
        factories = []
        for (host, port) in value:
            factories.append(ProxyFactory(host, port))
        self._hostports = value
        self.factories = factories
        if self.debug:
            log.msg("[DEBUG] hostport factories: {0}".format(self.factories))    

    def getNetmap(self):
        netmap = self._netmap
        if netmap is None:
            return []
        return list((str(nw), p, dh, dp) for nw, p, dh, dp in netmap)

    def setNetmap(self, value):
        if value is None:
            self._netmap = None
            self._netmap_factories = {}
            return
        netmap = [(IPNetwork(nw), p, dh, dp) for nw, p, dh, dp in value]
        self._netmap = netmap
        self._netmap_factories = {}

    def match_netmap(self, ipaddr, port):
        address = IPAddress(ipaddr)
        netmap = self._netmap
        if netmap is not None:
            for nw, p, dh, dp in netmap:
                if address.value & nw.value != nw.value:
                    continue 
                if p == '*' or p == port:
                    key = (dh, dp)
                    factories = self._netmap_factories
                    factory = factories.get(key, None)
                    if factory is None:
                        factory = ProxyFactory(dh, dp)
                        factories[key] = factory
                    return factory
        return None

    def buildProtocol(self, addr):
        debug = self.debug
        factories = self.factories
        factory_count = len(factories)
        client_ip = addr.host
        client_port = addr.port
        factory = self.match_netmap(client_ip, client_port)
        if not factory:
            if debug:
                log.msg("[DEBUG] No netmap for ({0}, {1})".format(client_ip, client_port))
            if factory_count > 0:
                quads = client_ip.split('.')
                x = int(quads[3])
                factory_index = x % factory_count
                factory = factories[factory_index]
                log.msg("[INFO] client_ip={0}, factory_index={1}.".format(client_ip, factory_index))
            else:
                protocol = GoodbyeProtocol()
                if debug:
                    log.msg("[DEBUG] No hostport factories.  Using `GoodbyeProtocol()`.")
                return protocol
        elif debug:
            log.msg("[DEBUG] Matched a netmap factory.")
        return factory.buildProtocol(addr)


class BalancerService(service.Service):
    def __init__(self, endpoint, hostports, netmap=None, admin_endpoint=None, admin_portal=None, debug=False):
        self.endpoint = endpoint
        self.hostports = hostports
        self.netmap = netmap
        self.admin_endpoint = admin_endpoint
        self.admin_portal = admin_portal
        self._ports = {}
        self.debug = debug

    def startService(self):
        debug = self.debug
        factory = Balancer(self.hostports, self.netmap)
        factory.debug = debug
        admin_portal = self.admin_portal
        admin_endpoint = self.admin_endpoint
        if admin_portal is not None and admin_endpoint is not None:
            admin_service, admin_website = make_ws(admin_portal, factory)
            ep = serverFromString(reactor, admin_endpoint)
            d0 = ep.listen(admin_service)
            d0.addCallback(self.set_listening_port, port_type='admin')            
        ep = serverFromString(reactor, self.endpoint)
        d = ep.listen(factory)
        d.addCallback(self.set_listening_port, port_type='proxy')

    def set_listening_port(self, port, port_type):
        self._ports[port_type] = port

    def stopService(self):
        """
        Stop the service.
        """
        rval = True
        for port_type, port in self._ports.iteritems():
            rval = (rval and port.stopListening())
        return rval

