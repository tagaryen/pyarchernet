from . import ARCHERLIB
from .sslcontext import SSLContext
from .channel import Channel, Handler
from .unordered_map import UnorderedMap
import ctypes

def server_on_connect(serverfd: int, fd: int, host: bytes, port: int):
    server = ServerChannel.get_server(serverfd)
    channel = server.init_channel(fd, str(host, 'utf-8'), port)
    server.handler.on_connect(channel)

def server_on_read(serverfd: int, fd: int, host: bytes, port: int, data: bytes, len: int):
    server = ServerChannel.get_server(serverfd)
    channel = server.get_channel(fd, str(host, 'utf-8'), port)
    server.handler.on_read(channel, data)

def server_on_error(serverfd: int, fd: int, host: bytes, port: int, error: bytes):
    server = ServerChannel.get_server(serverfd)
    channel = server.get_channel(fd, str(host, 'utf-8'), port)
    server.handler.on_error(channel, str(error, 'utf-8'))

def server_on_close(serverfd: int, fd: int, host: bytes, port: int):
    server = ServerChannel.get_server(serverfd)
    channel = server.get_channel(fd, str(host, 'utf-8'), port)
    server.handler.on_close(channel)

class ServerChannel:
    __SREVER_MAP = UnorderedMap()

    __host: str
    __port: int
    __fd: int

    __handler: Handler
    __sslctx: SSLContext
    __channel_map: UnorderedMap

    def __init__(self, host="127.0.0.1", port=9617):
        self.__host = host
        self.__port = port
        self.__fd = -1
        self.__sslctx = None
        self.__channel_map = UnorderedMap(257)

    
    @property
    def host(self)->str:
        '''远程地址
        '''
        return self.__host
    
    @property
    def port(self)->int:
        '''远程端口
        '''
        return self.__port
    
    @property
    def sslctx(self)->SSLContext:
        '''ssl证书上下文
        '''
        return self.__sslctx
    
    @sslctx.setter
    def sslctx(self, sslctx: SSLContext):
        '''ssl证书上下文
        '''
        self.__sslctx = sslctx
    
    def set_sslcontext(self, sslctx: SSLContext):
        '''ssl证书上下文
        '''
        self.sslctx = sslctx

    @property
    def handler(self):
        return self.__handler

    @handler.setter
    def handler(self, handler = None):
        self.__handler = handler

    def listen(self):     
        ARCHERLIB.ARCHER_server_channel_new_fd.restype = ctypes.c_int64
        self.__fd = ARCHERLIB.ARCHER_server_channel_new_fd()

        ServerChannel.__SREVER_MAP.put(self.__fd, self)
        
        c_fd = ctypes.c_int64(self.__fd)
        c_host = ctypes.c_char_p(self.host.encode('utf-8'))
        c_port = ctypes.c_int(self.port)
        c_ssl = ctypes.c_int(0)
        c_ca = ctypes.c_char_p(None)
        c_crt = ctypes.c_char_p(None)
        c_key = ctypes.c_char_p(None)
        c_en_crt = ctypes.c_char_p(None)
        c_en_key = ctypes.c_char_p(None)
        if self.sslctx is not None:
            c_ssl = ctypes.c_int(1)
            c_ca = ctypes.c_char_p(self.sslctx.ca.encode('utf-8'))
            c_crt = ctypes.c_char_p(self.sslctx.crt.encode('utf-8'))
            c_key = ctypes.c_char_p(self.sslctx.key.encode('utf-8'))
            c_en_crt = ctypes.c_char_p(self.sslctx.en_crt.encode('utf-8'))
            c_en_key = ctypes.c_char_p(self.sslctx.en_key.encode('utf-8'))
        
        OnConnectCb = ctypes.CFUNCTYPE(None, ctypes.c_int64, ctypes.c_int64, ctypes.c_char_p, ctypes.c_int)
        on_connect = OnConnectCb(server_on_connect)
        
        OnReadCb = ctypes.CFUNCTYPE(None, ctypes.c_int64, ctypes.c_int64, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int64)
        on_read = OnReadCb(server_on_read)
        
        OnErrorCb = ctypes.CFUNCTYPE(None, ctypes.c_int64, ctypes.c_int64, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p)
        on_error = OnErrorCb(server_on_error)
        
        OnCloseCb = ctypes.CFUNCTYPE(None, ctypes.c_int64, ctypes.c_int64, ctypes.c_char_p, ctypes.c_int)
        on_close = OnCloseCb(server_on_close)
        
        ARCHERLIB.ARCHER_server_channel_listen.restype = ctypes.c_char_p
        ret = ARCHERLIB.ARCHER_server_channel_listen(c_fd, c_host, c_port, c_ssl, c_ca, c_crt, c_key, c_en_crt, c_en_key, on_connect, on_read, on_error, on_close)
        if ret is not None and ret == "":
            raise Exception(ret)

    def close(self):
        c_fd = ctypes.c_int64(self.__fd)
        ARCHERLIB.ARCHER_server_channel_close(c_fd)

    @staticmethod
    def get_server(fd: int) -> Channel:
        server = ServerChannel.__SREVER_MAP.get(fd)
        if server is None:
            raise Exception("can not found ServerChannel")
        return server

    def init_channel(self, fd: int, host: str, port: int) -> Channel:
        channel = Channel(host, port, client_mode=False)
        channel.setfd(fd)
        self.__channel_map.put(fd, channel)
        return channel
    
    def get_channel(self, fd: int, host: str, port: int) -> Channel:
        channel = self.__channel_map.get(fd)
        if channel is None:
            channel = Channel(host, port)
            channel.__client_mode = False
            channel.__fd = fd
            self.__channel_map.put(fd, channel)
        return channel