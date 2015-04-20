
from __future__ import print_function
import base64
import exceptions
import hashlib
import json
from klein import Klein
from twisted.cred import error
from twisted.cred.credentials import IUsernamePassword, UsernamePassword
from twisted.cred.portal import IRealm
from twisted.internet import defer
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.python import log
from  twisted.web.http import BAD_REQUEST, UNAUTHORIZED, NOT_ALLOWED, NOT_FOUND
from twisted.web.server import Site
import werkzeug.exceptions
from zope.interface import Interface, Attribute, implements

def noop():
    pass

def decode_basic_auth(request):
    """
    Decodes basic auth info and returns (user, passwd) or None.
    """
    auth = request.getHeader("Authorization")
    if auth is None:
        return None
    if not auth.startswith("Basic "):
        return None
    encoded = auth[len("Basic "):]
    decoded = base64.decodestring(encoded)
    parts = decoded.split(":", 1)
    if len(parts) != 2:
        return None
    return tuple(parts)


class IAdminUser(Interface):
    username = Attribute('String username')


class AdminUser(object):
    implements(IAdminUser)
    username = None


class AdminRealm(object):
    implements(IRealm)

    def requestAvatar(avatarId, mind, *interfaces):
        if not IAdminUser in interfaces:
            return defer.fail(NotImplementedError("This realm only implements IBindProxyWSUser."))
        else:
            avatar = AdminUser()
            avatar.username = avatarId
            return defer.succeed((IAdminUser, avatar, noop))

class RESTError(Exception):
    @property
    def statusCode(self):
        return self.args[0]

    def __str__(self):
        args = self.args[1:]
        if len(args) == 1:
            return json.dumps(args[0])
        else:
            return json.dumps(args)


def parseBasicAuth(request):
    result = decode_basic_auth(request)
    if result is None:
        request.setResponseCode(UNAUTHORIZED)
        request.setHeader("WWW-Authenticate", 'Basic realm="BindProxyWS"')
        raise RESTError(UNAUTHORIZED, {"result": "not authorized"})
    user, passwd = result
    return user, passwd

@inlineCallbacks
def authenticate(request, user, passwd, portal):
    log.msg("[INFO] Attempting to authenticate '{0}' ...".format(user))
    client_ip = request.getClientIP()
    try:
        iface, avatar, logout = yield portal.login(UsernamePassword(user, passwd), None, IAdminUser)
    except (error.UnauthorizedLogin, exceptions.NotImplementedError) as ex:
        log.msg((
                "[ERROR] client_ip={client_ip}, login={login}: "
                "Unauthorized login attempt to admin web service.\n{err}").format(
            client_ip=client_ip, login=user, err=str(ex)))
        raise RESTError(UNAUTHORIZED, {"result": "not authorized"})
    except (Exception,) as ex:
        log.msg("[ERROR] {0}".format(str(ex)))
        raise RESTError(500, {'result': 'error'})


class AdminWebService(object):
    debug = False
    app = Klein()
    valid_funcs = frozenset([
        'hostports',
        'netmap'])

    def __init__(self, portal, dispatcher):
        self.portal = portal
        self.dispatcher = dispatcher

    @app.route('/<string:funcname>', methods=['GET', 'DELETE', 'PUT'])
    @inlineCallbacks
    def dispatcher(self, request, funcname):
        debug = self.debug
        if funcname not in self.valid_funcs:
            request.setResponseCode(NOT_FOUND)
            returnValue(json.dumps({'result': 'not found'}))
        method = request.method
        if debug:
            log.msg("[DEBUG] Received request for resource '/{0}_{1}'.".format(funcname, method))
        fn = getattr(self, '{0}_{1}'.format(funcname, method), None)
        if fn is None:
            request.setResponseCode(NOT_ALLOWED)
            returnValue(json.dumps({'result': 'not allowed'}))
        user, passwd = parseBasicAuth(request)
        yield authenticate(request, user, passwd, self.portal)
        returnValue(fn(request, user, passwd))

    def hostports_GET(self, request, user, passwd):
        request.setHeader("Content-Type", "application/json")
        client_ip = request.getClientIP()
        dispatcher = self.dispatcher
        hostPorts = dispatcher.getHostPorts()
        log.msg((
                "[INFO] client_ip={client_ip}, login={login}: "
                "Successfully retrieved hostports.").format(
                    client_ip=client_ip, login=user))
        return json.dumps(hostPorts)

    def hostports_DELETE(self, request, user, passwd):
        request.setHeader("Content-Type", "application/json")
        client_ip = request.getClientIP()
        dispatcher = self.dispatcher
        dispatcher.setHostPorts(None)
        log.msg((
                "[INFO] client_ip={client_ip}, login={login}: "
                "Successfully removed hostports.").format(
                    client_ip=client_ip, login=user))
        return json.dumps({"result": "ok"})

    def hostports_PUT(self, request, user, passwd):
        request.setHeader("Content-Type", "application/json")
        client_ip = request.getClientIP()
        try:
            o = json.load(request.content)
        except ValueError as ex:
            raise bad_request
        dispatcher = self.dispatcher
        dispatcher.setHostPorts(o)
        log.msg((
                "[INFO] client_ip={client_ip}, login={login}: "
                "Successfully set hostports.").format(
                    client_ip=client_ip, login=user))
        return json.dumps({"result": "ok"})

    def netmap_GET(self, request, user, passwd):
        request.setHeader("Content-Type", "application/json")
        client_ip = request.getClientIP()
        dispatcher = self.dispatcher
        netmap = dispatcher.getNetmap()
        log.msg((
                "[INFO] client_ip={client_ip}, login={login}: "
                "Successfully retrieved netmap.").format(
                    client_ip=client_ip, login=user))
        return json.dumps(netmap)

    def netmap_DELETE(self, request, user, passwd):
        request.setHeader("Content-Type", "application/json")
        client_ip = request.getClientIP()
        dispatcher = self.dispatcher
        dispatcher.setNetmap(None)
        log.msg((
                "[INFO] client_ip={client_ip}, login={login}: "
                "Successfully removed netmap.").format(
                    client_ip=client_ip, login=user))
        return json.dumps({"result": "ok"})

    def netmap_PUT(self, request, user, passwd):
        request.setHeader("Content-Type", "application/json")
        client_ip = request.getClientIP()
        bad_request = RESTError(BAD_REQUEST, {'result': 'bad request'})
        try:
            o = json.load(request.content)
        except ValueError as ex:
            raise bad_request
        dispatcher = self.dispatcher
        try:
            dispatcher.setNetmap(netmap)
        except ValueError:
            raise bad_request
        log.msg((
                "[INFO] client_ip={client_ip}, login={login}: "
                "Successfully set netmap.").format(
                    client_ip=client_ip, login=user))
        return json.dumps({"result": "ok"})

    @app.handle_errors(werkzeug.exceptions.NotFound)
    def error_handler_404(self, request, failure):
        log.msg("[ERROR] http_status=404, client_ip={client_ip}: {err}".format(
            client_ip=request.getClientIP(), err=str(failure)))
        request.setResponseCode(404)
        return '''{"result": "not found"}'''

    @app.handle_errors
    def error_handler(self, request, failure):
        if failure.type == RESTError:
            value = failure.value
            request.setResponseCode(value.statusCode)
            return str(value)
        else:
            request.setResponseCode(500)
            log.msg("[ERROR] http_status=500, client_ip={client_ip}: {err}".format(
                client_ip=request.getClientIP(), err=str(failure)))
            return json.dumps({"result": "error"})
        
             
def make_ws(portal, dispatcher):
    """
    Create and return the web service site, and web service.
    """
    ws = AdminWebService(portal, dispatcher)
    root = ws.app.resource()
    site = Site(root)
    return (site, ws)
