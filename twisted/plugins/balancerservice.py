
# Standard library
import sys

# Application modules
from proxies.adminws import AdminRealm
from proxies.tcp_dispatcher import BalancerService

# External modules
from twisted.application import internet
from twisted.application.service import IServiceMaker
from twisted.cred import credentials, portal, strcred
from twisted.plugin import getPlugins, IPlugin
from twisted.python import usage
from zope.interface import implements

class Options(usage.Options, strcred.AuthOptionMixin):
    supportedInterfaces = (credentials.IUsernamePassword,)
    optFlags = [
            ["debug", "d", "Debugging output."],
        ]
    optParameters = [
                        ["endpoint", "e", "tcp:10389", "The endpoint listen on (default 'tcp:10389')."],
                        ["hostport", "H", None, "Host and port separated by a colon.  "
                                                "May be specified multiple times."],
                        ["admin-endpoint", "a", None, "The endpoint listen on for the admin web service."],
                    ]

    def __init__(self):
        usage.Options.__init__(self)
        self["hostport"] = []

    def opt_hostport(self, value):
        self["hostport"].append(value)

    def postOptions(self):
        if len(self["hostport"]) < 1:
            raise usage.UsageError("Must specify at least one `hostport`.")

class MyServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "balancer"
    description = "TCP Proxy"
    options = Options

    def makeService(self, options):
        """
        Construct a server from a factory defined in myproject.
        """
        endpoint_str = options['endpoint']
        admin_endpoint_str = options['admin-endpoint']
        temp = options['hostport']
        debug = options['debug']
        hostports = []
        for x in temp:
            parts = x.split(":", 1)
            hostports.append((parts[0], int(parts[1])))
        # AuthN for admin web service.
        realm = AdminRealm()
        checkers = options.get("credCheckers", None)
        if checkers is not None and admin_endpoint_str is not None:
            admin_portal = portal.Portal(realm, checkers)
        else:
            admin_portal = None
        # Create the service.
        service = BalancerService(
            endpoint_str, 
            hostports, 
            admin_endpoint=admin_endpoint_str, 
            admin_portal=admin_portal,
            debug=debug)
        return service


# Now construct an object which *provides* the relevant interfaces
# The name of this variable is irrelevant, as long as there is *some*
# name bound to a provider of IPlugin and IServiceMaker.
serviceMaker = MyServiceMaker()
