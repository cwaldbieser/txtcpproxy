
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
from  twisted.web.http import BAD_REQUEST, UNAUTHORIZED
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
    pass

def parseBasicAuth(request):
    result = decode_basic_auth(request)
    if result is None:
        request.setResponseCode(UNAUTHORIZED)
        request.setHeader("WWW-Authenticate", 'Basic realm="BindProxyWS"')
        raise RESTError("""{"result": "not authorized"}""")
    user, passwd = result
    return user, passwd

def authenticate(request, user, passwd, portal):
    client_ip = request.getClientIP()
    try:
        iface, avatar, logout = yield portal.login(UsernamePassword(user, passwd), None, IAdminUser)
    except (error.UnauthorizedLogin, exceptions.NotImplementedError) as ex:
        log.msg((
                "[ERROR] client_ip={client_ip}, login={login}: "
                "Unauthorized login attempt to admin web service.\n{err}").format(
            client_ip=client_ip, login=user, err=str(ex)))
        request.setResponseCode(UNAUTHORIZED)
        returnValue("""{"result": "not authorized"}""")
    except Exception as ex:
        log.msg("[ERROR] {0}".format(str(ex)))
        request.setResponseCode(500)
        returnValue('''{"result": "error"}''')

def restwrap(fn):
    def _inner(*args, **kwds):
        try:
            return fn(*args, **kwds)
        except RESTError as ex:
            return str(ex)
    return _inner


class AdminWebService(object):
    app = Klein()

    def __init__(self, portal, dispatcher):
        self.portal = portal
        self.dispatcher = dispatcher

    @app.route('/netmap', methods=['DELETE'])
    @restwrap
    @inlineCallbacks
    def netmap_DELETE(self, request):
        request.setHeader("Content-Type", "application/json")
        user, passwd = parseBasicAuth(request)
        authenticate(request, user, passwd, self.portal)
        client_ip = request.getClientIP()
        dispatcher = self.dispatcher
        dispatcher.netmap = None
        log.msg((
                "[INFO] client_ip={client_ip}, login={login}: "
                "Successfully removed netmap.").format(
                    client_ip=client_ip, login=user, dn=dn))
        returnValue('''{"result": "ok"}''')

    @app.handle_errors(werkzeug.exceptions.NotFound)
    def error_handler_404(self, request, failure):
        log.msg("[ERROR] http_status=404, client_ip={client_ip}: {err}".format(
            client_ip=request.getClientIP(), err=str(failure)))
        request.setResponseCode(404)
        return '''{"result": "not found"}'''

    @app.handle_errors
    def error_handler_500(self, request, failure):
        request.setResponseCode(500)
        log.msg("[ERROR] http_status=500, client_ip={client_ip}: {err}".format(
            client_ip=request.getClientIP(), err=str(failure)))
        return '''{"result": "error"}'''
        
             
def make_ws(portal, dispatcher):
    """
    Create and return the web service site, and web service.
    """
    ws = AdminWebService(portal, dispatcher)
    root = ws.app.resource()
    site = Site(root)
    return (site, ws)
