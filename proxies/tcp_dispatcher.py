
#-----------------------------------------------------------------------------
# A TCP dispatcher (hash based on client IP)
# Ref: http://stackoverflow.com/questions/4096061/general-question-regarding-wether-or-not-use-twisted-in-tcp-proxy-project 
#-----------------------------------------------------------------------------

from twisted.application import service
from twisted.internet import reactor, defer, ssl, protocol
from twisted.internet.endpoints import serverFromString
from twisted.internet.protocol import Factory
from twisted.protocols.portforward import ProxyServer, ProxyFactory
from twisted.python import log

class Balancer(Factory):
    def __init__(self, hostports):
        self.factories = []
        for (host, port) in hostports:
            self.factories.append(ProxyFactory(host, port))

    def buildProtocol(self, addr):
	factories = self.factories
	factory_count = len(factories)
	client_ip = addr.host
	client_port = addr.port
	quads = client_ip.split('.')
	x = int(quads[3])
	factory_index = x % factory_count
	factory = factories[factory_index]
	log.msg("[DEBUG] client_ip={0}, factory_index={1}.".format(client_ip, factory_index))
        return factory.buildProtocol(addr)


class BalancerService(service.Service):
    def __init__(self, endpoint, hostports):
        self.endpoint = endpoint
        self.hostports = hostports

    def startService(self):
        factory = Balancer(self.hostports)
        ep = serverFromString(reactor, self.endpoint)
        d = ep.listen(factory)
        d.addCallback(self.set_listening_port)

    def stopService(self):
        """
        Stop the service.
        """
        if self._port is not None:
            return self._port.stopListening()

    def set_listening_port(self, port):
        self._port = port

