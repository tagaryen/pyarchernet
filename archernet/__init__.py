__package__ = "archernet"

import ctypes, os
import platform

ARCH = platform.machine()

ARCHERLIB = None
if platform.system().lower() == 'windows':
    ARCHERLIB = ctypes.CDLL(os.path.dirname(os.path.abspath(__file__)) + '/lib/libarchernet.dll')
elif platform.system().lower() == 'linux':
    if ARCH.lower() == 'x86_64' or 'amd64':
        ARCHERLIB = ctypes.CDLL(os.path.dirname(os.path.abspath(__file__)) + '/lib/libarchernet-x86-64.so')
    elif ARCH.lower() == 'arm64' or 'aarch64':
        ARCHERLIB = ctypes.CDLL(os.path.dirname(os.path.abspath(__file__)) + '/lib/libarchernet-aarch64.so')
    else:
        raise Exception(f"platform arch '{ARCH}' not supported")
else:
    raise Exception(f"platform '{platform.system()}' not supported")
ARCHERLIB.ARCHER_net_init()

from .channel import Channel
from .server_channel import ServerChannel
from .sslcontext import SSLContext
from .handlers import Handler, ChannelContext, HandlerList
from .fair_lock import FairLock
from .arpc import ARPCClient, ARPCServer, AbstractUrlMatcher
from .http import HttpRequest, HttpResponse, HttpServer, HttpStatusCode, BlockedHttpHandler, HttpClient, HttpClientResponse, HttpError, Multipart, FormData, StreamWriter
from .rs_client import RSClient
from .exception import format_exception
from .pro_http import ProHttpRequest, ProHttpResponse, ProHttpServer, HttpMessageListenner

__all__ = ['Channel', 'ServerChannel', 'SSLContext','Handler', 'ChannelContext','HandlerList', 'FairLock', 
           'AbstractUrlMatcher', 'ARPCClient', 'ARPCServer',
           'HttpRequest', 'HttpResponse', 'HttpServer', 'HttpStatusCode', 'BlockedHttpHandler', 'HttpClient', 'HttpClientResponse', 'HttpError', 'Multipart', 'FormData', 'StreamWriter',
           'RSClient',
           'format_exception',
           'ProHttpRequest', 'ProHttpResponse', 'ProHttpServer', 'HttpMessageListenner']


