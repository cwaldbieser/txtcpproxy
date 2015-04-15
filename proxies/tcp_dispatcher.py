
#-----------------------------------------------------------------------------
# A TCP dispatcher (hash based on client IP)
# Ref: http://stackoverflow.com/questions/4096061/general-question-regarding-wether-or-not-use-twisted-in-tcp-proxy-project 
#-----------------------------------------------------------------------------

from netaddr import IPAddress, IPNetwork
from twisted.application import service
from twisted.internet import reactor, defer, ssl, protocol
from twisted.internet.endpoints import serverFromString
from twisted.internet.protocol import Factory
from twisted.protocols.portforward import ProxyServer, ProxyFactory
from twisted.python import log

class Balancer(Factory):
    """
    `netmap` should be a sequence of tuples:
        (client_ip_network, client_port, dst_host, dst_port)

    `client_ip_network` should be a string representation of an IP network (e.g. "192.0.2.0/24").
    `client_port` may be an integer or '*' (any port matches).
    `dst_host` is the remote host.
    `dst_port` is the remote port.
    """
    def __init__(self, hostports, netmap=None):
        self.hostports = hostports
        self.netmap = netmap

    @property
    def hostports(self):
        return list(self.hostports)

    @hostports.setter
    def hostports(self, value):
        self.factories = []
        self._hostports = value
        for (host, port) in hostports:
            self.factories.append(ProxyFactory(host, port))

    @property
    def netmap(self):
        return list((str(nw), p, dh, dp) for nw, p, dh, dp in self._netmap)

    @netmap.setter
    def netmap(self, value):
        if value is None:
            self._netmap = None
            self._netmap_factories = {}
            return
        self._netmap = [(IPNetwork(nw), p, dh, dp) for nw, p, dh, dp in value]
        self._netmap_factories = {}

    def match_netmap(self, ipaddr, port):
        address = IPAddress(ipaddr)
        netmap = self._netmap
        for nw, p, dh, dp in netmap:
            if address.value & network.value != network.value:
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
        factories = self.factories
        factory_count = len(factories)
        client_ip = addr.host
        client_port = addr.port
        factory = self.match_netmap(client_ip, client_port)
        if not factory:
            quads = client_ip.split('.')
            x = int(quads[3])
            factory_index = x % factory_count
            factory = factories[factory_index]
            log.msg("[INFO] client_ip={0}, factory_index={1}.".format(client_ip, factory_index))
        return factory.buildProtocol(addr)


class BalancerService(service.Service):
    def __init__(self, endpoint, hostports, netmap=None, startedCallback=None):
        self.endpoint = endpoint
        self.hostports = hostports
        self.netmap = netmap

    def startService(self):
        factory = Balancer(self.hostports, self.netmap)
        ep = serverFromString(reactor, self.endpoint)
        d = ep.listen(factory)
        d.addCallback(self.set_listening_port)
        if startedCallback is not None:
            d2 = defer.Deferred()
            d2.addCallback(startedCallback, factory)

    def stopService(self):
        """
        Stop the service.
        """
        if self._port is not None:
            return self._port.stopListening()

    def set_listening_port(self, port):
        self._port = port

