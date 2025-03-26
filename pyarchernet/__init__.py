__package__ = "archernet"

import ctypes, os

ARCHERLIB = ctypes.CDLL(os.path.dirname(os.path.abspath(__file__)) + '/lib/libarchernet.dll')

from .channel import Channel,Handler
from .server_channel import ServerChannel
from .sslcontext import SSLContext

__all__ = ['Channel', 'Handler', 'ServerChannel', 'SSLContext']