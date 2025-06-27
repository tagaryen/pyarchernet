from . import ARCHERLIB
from .channel import Channel
from .handlerlist import HandlerList
from .handlers import NetError
from .sslcontext import SSLContext
from .unordered_map import UnorderedMap

import ctypes, threading, traceback

class ServerChannel:
    # __SREVER_MAP = UnorderedMap()

    __host: str
    __port: int
    __fd: int

    __handler_list: HandlerList
    __sslctx: SSLContext
    __channel_map: UnorderedMap

    def __init__(self, host="127.0.0.1", port=9617, thread_num=1, sslctx: SSLContext = None, handlerlist:HandlerList = None):
        self.__check(host, port)
        self.__host = host
        self.__port = port
        if thread_num > 128:
            thread_num = 128
        if thread_num < 0:
            thread_num = 0
        self.__thread_num = thread_num
        self.__fd = -1
        if sslctx is not None and sslctx.is_client_mode:
            raise NetError("can not use a client-side SSLContext at server side")
        if sslctx is not None:
            self.__ssl = True
        else:
            self.__ssl = False
        self.__sslctx = sslctx
        self.__channel_map = UnorderedMap(257)
        self.__handler_list = handlerlist

    def __check(self, host, port):
        if host is None or port is None or type(host) is not str or type(port) is not int:
            raise NetError("invalid host or port {}, {}".format(host, port))
        if port <= 0 or port >= 65536:
            raise NetError("invalid port {}".format(port))

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
        if sslctx is not None and sslctx.is_client_mode:
            raise NetError("can not use a client-side SSLContext at server side")
        self.__sslctx = sslctx

    @property
    def handlerlist(self) -> HandlerList:
        return self.__handler_list
    
    def set_handlerlist(self, handlerlist:HandlerList):
        self.__handler_list = handlerlist

    def listen(self):
        self.__is_async = False
        self.__start_listen()

    def listen_async(self):
        self.__is_async = True
        self.__start_listen()


    def __start_listen(self):
        ARCHERLIB.ARCHER_server_channel_new_fd.restype = ctypes.c_int64
        self.__fd = ARCHERLIB.ARCHER_server_channel_new_fd()

        # ServerChannel.__SREVER_MAP.put(self.__fd, self)
        
        c_fd = ctypes.c_int64(self.__fd)
        c_host = ctypes.c_char_p(self.host.encode('utf-8'))
        c_port = ctypes.c_int(self.port)
        c_thread = ctypes.c_int(self.__thread_num)
        if self.sslctx is not None:
            c_max_ver = ctypes.c_int32(self.sslctx.max_version)
            c_min_ver = ctypes.c_int32(self.sslctx.max_version)
            c_ssl = ctypes.c_int(1)
            if self.sslctx.ca is not None:
                c_ca = ctypes.c_char_p(self.sslctx.ca.encode('utf-8'))
            if self.sslctx.crt is not None and self.sslctx.key is not None:
                c_crt = ctypes.c_char_p(self.sslctx.crt.encode('utf-8'))
                c_key = ctypes.c_char_p(self.sslctx.key.encode('utf-8'))
            if self.sslctx.en_crt is not None and self.sslctx.en_key is not None:
                c_en_crt = ctypes.c_char_p(self.sslctx.en_crt.encode('utf-8'))
                c_en_key = ctypes.c_char_p(self.sslctx.en_key.encode('utf-8'))
        else:
            c_max_ver = ctypes.c_int32(0)
            c_min_ver = ctypes.c_int32(0)
            c_ssl = ctypes.c_int(0)
            c_ca = ctypes.c_char_p(None)
            c_crt = ctypes.c_char_p(None)
            c_key = ctypes.c_char_p(None)
            c_en_crt = ctypes.c_char_p(None)
            c_en_key = ctypes.c_char_p(None)
        
        
        def server_on_connect(fd: int, host: bytes, port: int):
            channel = self.__get_channel(fd, str(host, 'utf-8'), port)
            if self.handlerlist is not None:
                try:
                    ctx = self.handlerlist.find_channel_contxet(channel)
                    if ctx is not None:
                        ctx.handler.on_connect(ctx)
                except Exception as e:
                    if ctx is not None:
                        ctx.handler.on_error(ctx, e)
                    else: 
                        traceback.print_exception(e)

        def server_on_read(fd: int, host: bytes, port: int, data_ptr: ctypes.c_void_p, data_size: int):
            if self.handlerlist is not None:
                try:
                    channel = self.__get_channel(fd, str(host, 'utf-8'), port)
                    data = bytes((ctypes.c_char * data_size).from_address(data_ptr))
                    ctx = self.handlerlist.find_channel_contxet(channel)
                    if ctx is not None:
                        ctx.handler.on_read(ctx, data)
                except Exception as e:
                    if ctx is not None:
                        ctx.handler.on_error(ctx, e)
                    else: 
                        traceback.print_exception(e)

        def server_on_error(fd: int, host: bytes, port: int, error: bytes):
            if self.handlerlist is not None:
                try:
                    channel = self.__get_channel(fd, str(host, 'utf-8'), port)
                    ctx = self.handlerlist.find_channel_contxet(channel)
                    if ctx is not None:
                        ctx.handler.on_error(ctx, NetError(str(error, 'utf-8')))
                    else:
                        print("ERROR: {}".format(str(error, 'utf-8')))
                except Exception as e:
                    traceback.print_exception(e)

        def server_on_close(fd: int, host: bytes, port: int):
            channel = self.__get_channel(fd, str(host, 'utf-8'), port)
            if self.handlerlist is not None:
                try:
                    ctx = self.handlerlist.find_channel_contxet(channel)
                    if ctx is not None:
                        ctx.handler.on_close(ctx)
                except Exception as e:
                    if ctx is not None:
                        ctx.handler.on_error(ctx, e)
                    else: 
                        traceback.print_exception(e)

        OnConnectCb = ctypes.CFUNCTYPE(None, ctypes.c_int64, ctypes.c_char_p, ctypes.c_int)
        on_connect = OnConnectCb(server_on_connect)
        
        OnReadCb = ctypes.CFUNCTYPE(None, ctypes.c_int64, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_int64)
        on_read = OnReadCb(server_on_read)
        
        OnErrorCb = ctypes.CFUNCTYPE(None, ctypes.c_int64, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p)
        on_error = OnErrorCb(server_on_error)
        
        OnCloseCb = ctypes.CFUNCTYPE(None, ctypes.c_int64, ctypes.c_char_p, ctypes.c_int)
        on_close = OnCloseCb(server_on_close)
        
        def block_listen():
            ARCHERLIB.ARCHER_server_channel_listen.restype = ctypes.c_char_p
            ret = ARCHERLIB.ARCHER_server_channel_listen(c_fd, c_host, c_port, c_ssl, c_thread, c_ca, c_crt, c_key, c_en_crt, c_en_key, c_max_ver, c_min_ver, on_connect, on_read, on_error, on_close)
            if ret is not None and len(ret) > 0:
                raise NetError(str(ret, 'utf-8'))
            
        if self.__is_async:
            self.__thread = threading.Thread(target=block_listen)
            self.__thread.start()
        else:
            block_listen()

    def close(self):
        c_fd = ctypes.c_int64(self.__fd)
        ARCHERLIB.ARCHER_server_channel_close(c_fd)
    
    def __get_channel(self, fd: int, host: str, port: int) -> Channel:
        channel = self.__channel_map.get(fd)
        if channel is None:
            channel = Channel(host, port, client_mode=False)
            channel.setfd(fd)
            self.__channel_map.put(fd, channel)
        return channel