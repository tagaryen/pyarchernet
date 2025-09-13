__package__ = "pyarchernet"

import ctypes, os
import platform

ARCHERLIB = None
if platform.system().lower() == 'windows':
    ARCHERLIB = ctypes.CDLL(os.path.dirname(os.path.abspath(__file__)) + '/lib/libarchernet.dll')
    ARCHERLIB.ARCHER_net_init()
elif platform.system().lower() == 'linux':
    ARCHERLIB = ctypes.CDLL(os.path.dirname(os.path.abspath(__file__)) + '/lib/libarchernet.so')
    ARCHERLIB.ARCHER_net_init()
else:
    raise Exception(f"platform '{platform.system()}' not supported")

from .channel import Channel
from .server_channel import ServerChannel
from .sslcontext import SSLContext
from .handlers import Handler, BaseFrameHandler, ChannelContext, HandlerList
from .fair_lock import FairLock
from .arpc import ARPCClient, ARPCServer, AbstractUrlMatcher
from .http import HttpRequest, HttpResponse, HttpServer, HttpStatusCode, BlockedHttpHandler, HttpClient, HttpClientResponse, HttpError, Multipart, FormData, StreamWriter

__all__ = ['Channel', 'ServerChannel', 'SSLContext','Handler', 'ChannelContext','HandlerList', 'BaseFrameHandler', 'FairLock', 
           'AbstractUrlMatcher', 'ARPCClient', 'ARPCServer',
           'HttpRequest', 'HttpResponse', 'HttpServer', 'HttpStatusCode', 'BlockedHttpHandler', 'HttpClient', 'HttpClientResponse', 'HttpError', 'Multipart', 'FormData', 'StreamWriter']


