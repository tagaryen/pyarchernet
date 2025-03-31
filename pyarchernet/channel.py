from . import ARCHERLIB
from .sslcontext import SSLContext
from .handlerlist import HandlerList

import ctypes, json, threading, traceback

class Channel():
    __host: str
    __port: int
    __client_mode: bool
    __fd: int

    __sslctx: SSLContext
    __handler_list: HandlerList

    __active: bool

    def __init__(self, host="127.0.0.1", port=9617, client_mode=True, sslctx: SSLContext = None, handlerlist:HandlerList = None):
        self.__check(host, port)
        self.__host = host
        self.__port = port
        self.__fd = 0
        self.__client_mode = client_mode
        if sslctx is not None and not sslctx.is_client_mode:
            raise Exception("can not use a server-side SSLContext at client side")
        self.__sslctx = sslctx
        self.__handler_list = handlerlist
        self.__active = False

    def __check(self, host, port):
        if host is None or port is None or type(host) is not str or type(port) is not int:
            raise Exception(f"invalid host or port {host}, {port}")
        if port <= 0 or port >= 65536:
            raise Exception(f"invalid port {port}")
    
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
        if sslctx is not None and not sslctx.is_client_mode:
            raise Exception("can not use a server-side SSLContext at client side")
        self.__sslctx = sslctx
    
    @property
    def active(self) -> bool:
        return self.__active

    @property
    def client_mode(self)->bool:
        return self.__client_mode

    @property
    def handlerlist(self)->HandlerList:
        return self.__handler_list

    def set_handlerlist(self, handlerlist:HandlerList):
        self.__handler_list = handlerlist

    def setfd(self, fd: int):
        '''do not call this function
           this is for server side new channel
        '''
        if self.__fd != 0 or fd == 0:
            raise Exception("can not set fd")
        self.__fd = fd

    def connect(self):
        '''connect to remote server
        '''        
        if not self.__client_mode:
            raise Exception("server side channel can not connect to remote")

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
            if self.sslctx.ca is not None:
                c_ca = ctypes.c_char_p(self.sslctx.ca.encode('utf-8'))
            if self.sslctx.crt is not None and self.sslctx.key is not None:
                c_crt = ctypes.c_char_p(self.sslctx.crt.encode('utf-8'))
                c_key = ctypes.c_char_p(self.sslctx.key.encode('utf-8'))
            if self.sslctx.en_crt is not None and self.sslctx.en_key is not None:
                c_en_crt = ctypes.c_char_p(self.sslctx.en_crt.encode('utf-8'))
                c_en_key = ctypes.c_char_p(self.sslctx.en_key.encode('utf-8'))
            if self.sslctx.matched_hostname is not None:
                c_matched_host = ctypes.c_char_p(self.sslctx.matched_hostname.encode('utf-8'))
            if self.sslctx.named_curves is not None:
                c_named_curves = ctypes.c_char_p(self.sslctx.named_curves.encode('utf-8'))
        # 调用C函数
        
        def client_on_error(error: bytes):
            if self.handlerlist is not None:
                try:
                    ctx = self.handlerlist.find_channel_contxet(self)
                    if ctx is not None:
                        ctx.handler.on_error(ctx, Exception(str(error, 'utf-8')))
                    else:
                        print(str(error, 'utf-8'))
                except Exception as e:
                    print(str(e))
                    stack_trace = traceback.format_exc()
                    print(stack_trace)


        def client_on_connect():
            self.on_connect()
            if self.handlerlist is not None:
                try:
                    ctx = self.handlerlist.find_channel_contxet(self)
                    if ctx is not None:
                        ctx.handler.on_connect(ctx)
                except Exception as e:
                    if ctx is not None:
                        ctx.handler.on_error(ctx, e)
                    else:
                        print(str(e))
                        stack_trace = traceback.format_exc()
                        print(stack_trace)

        def client_on_read(data_ptr: ctypes.c_void_p, data_size: int):
            if self.handlerlist is not None:
                try:
                    ctx = self.handlerlist.find_channel_contxet(self)
                    data = bytes((ctypes.c_char * data_size).from_address(data_ptr))
                    if ctx is not None:
                        ctx.handler.on_read(ctx, data)
                except Exception as e:
                    if ctx is not None:
                        ctx.handler.on_error(ctx, e)
                    else:
                        print(str(e))
                        stack_trace = traceback.format_exc()
                        print(stack_trace)

        def client_on_close():
            self.on_close()
            if self.handlerlist is not None:
                try:
                    ctx = self.handlerlist.find_channel_contxet(self)
                    if ctx is not None:
                        ctx.handler.on_close(ctx)
                except Exception as e:
                    if ctx is not None:
                        ctx.handler.on_error(ctx, e)
                    else:
                        print(str(e))
                        stack_trace = traceback.format_exc()
                        print(stack_trace)


        OnConnectCb = ctypes.CFUNCTYPE(None)
        on_connect = OnConnectCb(client_on_connect)
        
        OnReadCb = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_int32)
        on_read = OnReadCb(client_on_read)
        
        OnErrorCb = ctypes.CFUNCTYPE(None, ctypes.c_char_p)
        on_error = OnErrorCb(client_on_error)
        
        OnCloseCb = ctypes.CFUNCTYPE(None)
        on_close = OnCloseCb(client_on_close)

        def async_connect():
            ARCHERLIB.ARCHER_channel_connect.restype = ctypes.c_char_p
            ret = ARCHERLIB.ARCHER_channel_connect(c_fd, c_host, c_port, c_verify_peer, c_ca, c_crt, c_key, c_en_crt, c_en_key, c_matched_host, c_named_curves,
                                            on_connect, on_read, on_error, on_close)
            if ret is not None and ret == "":
                raise Exception(ret)
        self.__thread = threading.Thread(target=async_connect)
        self.__thread.start()
    
    def on_connect(self):
        self.__active = True

    def on_close(self):
        self.__active = False

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
        c_data = ctypes.create_string_buffer(data_bytes)
        c_size = ctypes.c_int32(len(data_bytes))
        ARCHERLIB.ARCHER_channel_write.restype = ctypes.c_void_p
        ARCHERLIB.ARCHER_channel_write(c_fd, c_data, c_size)

    
    def close(self):
        if not self.__client_mode:
            return 
        c_fd = ctypes.c_int64(self.__fd)
        ARCHERLIB.ARCHER_channel_close(c_fd)
