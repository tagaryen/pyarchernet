__package__ = "pyarchernet"

import ctypes, os
import platform

ARCHERLIB = None
if platform.system().lower() == 'windows':
    ARCHERLIB = ctypes.CDLL(os.path.dirname(os.path.abspath(__file__)) + '/lib/libarchernet.dll')
elif platform.system().lower() == 'linux':
    ARCHERLIB = ctypes.CDLL(os.path.dirname(os.path.abspath(__file__)) + '/lib/libarchernet.so')
else:
    raise Exception(f"platform '{platform.system()}' not supported")

from .channel import Channel
from .server_channel import ServerChannel
from .sslcontext import SSLContext
from .handlers import Handler, BaseFrameHandler, ChannelContext
from .handlerlist import HandlerList
from .fair_lock import FairLock
from .arpc import ARPCClientMessageListenner, ARPCServerMessageListenner, ARPCClient, ARPCServer

__all__ = ['Channel', 'ServerChannel', 'SSLContext','Handler', 'ChannelContext','HandlerList', 'BaseFrameHandler', 'FairLock', 'ARPCClientMessageListenner', 'ARPCServerMessageListenner', 'ARPCClient', 'ARPCServer']


