from . import ARCHERLIB
from .sslcontext import SSLContext
from abc import abstractmethod

import ctypes
import json



def client_on_connect(host: bytes, port: int):
    channel = Channel.get_channel(str(host, 'utf-8'), port)
    channel.handler.on_connect(channel)

def client_on_read(host: bytes, port: int, data: bytes, len: int):
    channel = Channel.get_channel(str(host, 'utf-8'), port)
    channel.handler.on_read(channel, data)

def client_on_error(host: bytes, port: int, error: bytes):
    channel = Channel.get_channel(str(host, 'utf-8'), port)
    channel.handler.on_error(channel, str(error, 'utf-8'))

def client_on_close(host: bytes, port: int):
    channel = Channel.get_channel(str(host, 'utf-8'), port)
    channel.handler.on_close(channel)


class Channel():
    __CHANNEL_MAP = {}

    __host: str
    __port: int
    __client_mode: bool
    __fd: int

    __sslctx: SSLContext
    __handler: None

    def __init__(self, host="127.0.0.1", port=9617, client_mode=True):
        self.__host = host
        self.__port = port
        self.__fd = 0
        self.__client_mode = client_mode
        self.__sslctx = None

    
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
    
    @property
    def client_mode(self)->bool:
        return self.__client_mode

    @property
    def handler(self):
        return self.__handler

    @handler.setter
    def handler(self, handler = None):
        self.__handler = handler

    def setfd(self, fd: int):
        if self.__fd != 0 or fd == 0:
            raise Exception("can not set fd")
        self.__fd = fd

    def connect(self):
        '''int64_t fd, const char *host, int port, 
           int verify_peer, const char *ca, const char *crt, const char *key, const char *en_crt, const char *en_key, 
           const char *match_name, const char *named_curves,
           PyOnconnectCb on_connect, PyOnreadCb on_read, PyOnerrorCb on_error, PyOncloseCb on_close
        '''        
        if not self.__client_mode:
            raise Exception("server side channel can not connect to remote")
        
        key = self.host + str(self.port)
        Channel.__CHANNEL_MAP[key] = self

        ARCHERLIB.ARCHER_channel_new_fd.restype = ctypes.c_int64
        self.__fd = ARCHERLIB.ARCHER_channel_new_fd()

        c_fd = ctypes.c_int64(self.__fd)
        c_host = ctypes.c_char_p(self.host.encode('utf-8'))
        c_port = ctypes.c_int16(self.port)
        c_verify_peer = ctypes.c_int(-1)
        c_ca = ctypes.c_char_p(None)
        c_crt = ctypes.c_char_p(None)
        c_key = ctypes.c_char_p(None)
        c_en_crt = ctypes.c_char_p(None)
        c_en_key = ctypes.c_char_p(None)
        c_matched_host = ctypes.c_char_p(None)
        c_named_curves = ctypes.c_char_p(None)
        if self.sslctx is not None:
            c_verify_peer = ctypes.c_int(1 if self.sslctx.verify_peer else 0)
            c_ca = ctypes.c_char_p(self.sslctx.ca.encode('utf-8'))
            c_crt = ctypes.c_char_p(self.sslctx.crt.encode('utf-8'))
            c_key = ctypes.c_char_p(self.sslctx.key.encode('utf-8'))
            c_en_crt = ctypes.c_char_p(self.sslctx.en_crt.encode('utf-8'))
            c_en_key = ctypes.c_char_p(self.sslctx.en_key.encode('utf-8'))
            c_matched_host = ctypes.c_char_p(self.sslctx.matched_hostname.encode('utf-8'))
            c_named_curves = ctypes.c_char_p(self.sslctx.named_curves.encode('utf-8'))
        # 调用C函数
        
        OnConnectCb = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_int)
        on_connect = OnConnectCb(client_on_connect)
        
        OnReadCb = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int32)
        on_read = OnReadCb(client_on_read)
        
        OnErrorCb = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p)
        on_error = OnErrorCb(client_on_error)
        
        OnCloseCb = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_int, )
        on_close = OnCloseCb(client_on_close)

        ARCHERLIB.ARCHER_channel_connect.restype = ctypes.c_char_p
        ret = ARCHERLIB.ARCHER_channel_connect(c_fd, c_host, c_port, c_verify_peer, c_ca, c_crt, c_key, c_en_crt, c_en_key, c_matched_host, c_named_curves,
                                         on_connect, on_read, on_error, on_close)
        if ret is not None and ret == "":
            raise Exception(ret)
    

    def send(self, data: bytes | str):
        data_bytes = None
        if isinstance(data, bytes):
            data_bytes = data
        elif isinstance(data, str):
            data_bytes = data.encode('utf-8')
        elif isinstance(data, dict) or isinstance(data, list):
            data_bytes = json.dumps(data).encode('utf-8')
        else :
            raise Exception(f"can not send type {type(data)}")
        c_fd = ctypes.c_int64(self.__fd)
        c_data = ctypes.c_char_p(data_bytes)
        c_size = ctypes.c_int32(len(data_bytes))
        ARCHERLIB.ARCHER_channel_write.restype = ctypes.c_void_p
        ARCHERLIB.ARCHER_channel_write(c_fd, c_data, c_size)

    
    def close(self):
        if not self.__client_mode:
            return 
        c_fd = ctypes.c_int64(self.__fd)
        ARCHERLIB.ARCHER_channel_close(c_fd)

    @staticmethod
    def get_channel(host: str, port: int):
        key = host + str(port)
        if key not in Channel.__CHANNEL_MAP:
            raise Exception("can not found channel " + key)
        return Channel.__CHANNEL_MAP[key]

class Handler():

    @abstractmethod
    def on_connect(self, channel: Channel):
        ''' 当连接进入时
        '''
        pass

    @abstractmethod
    def on_read(self, channel: Channel, data: bytes):
        ''' 当有数据被读取时
        '''
        pass

    @abstractmethod
    def on_error(self, channel: Channel, error: str):
        ''' 当有错误发生时
        '''
        pass

    @abstractmethod
    def on_close(self, channel: Channel):
        ''' 当连接关闭时
        '''
        pass