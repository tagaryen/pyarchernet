from . import ARCHERLIB

from .sslcontext import SSLContext
from .handlers import NetError

import ctypes, threading
from typing import Dict
from abc import abstractmethod

ARCHERLIB.ARCHER_http_server_new_ssl_fd.restype = ctypes.c_int64
ARCHERLIB.ARCHER_http_server_new_fd.restype = ctypes.c_int64
ARCHERLIB.ARCHER_http_server_listen.restype = ctypes.c_char_p
ARCHERLIB.ARCHER_http_server_close.restype = ctypes.c_void_p

ARCHERLIB.ARCHER_http_request_get_header.restype = ctypes.c_char_p
ARCHERLIB.ARCHER_http_request_get_query.restype = ctypes.c_char_p
ARCHERLIB.ARCHER_http_request_get_content_type.restype = ctypes.c_char_p
ARCHERLIB.ARCHER_http_request_get_queries_size.restype = ctypes.c_int
ARCHERLIB.ARCHER_http_request_get_query_key.restype = ctypes.c_char_p
ARCHERLIB.ARCHER_http_request_get_query_val.restype = ctypes.c_char_p
ARCHERLIB.ARCHER_http_request_read_body.restype = ctypes.c_int

ARCHERLIB.ARCHER_http_response_set_status.restype = ctypes.c_void_p
ARCHERLIB.ARCHER_http_response_set_header.restype = ctypes.c_void_p
ARCHERLIB.ARCHER_http_response_send_body.restype = ctypes.c_void_p
ARCHERLIB.ARCHER_http_response_send_start.restype = ctypes.c_void_p
ARCHERLIB.ARCHER_http_response_send_chunk.restype = ctypes.c_void_p
ARCHERLIB.ARCHER_http_response_send_end.restype = ctypes.c_void_p

class ProHttpRequest():

    __fd: int
    __c_fd: int
    __uri: str
    __method: str
    __headers: Dict
    __queries: Dict
    __queries_parsed: bool
    __content_type: str

    def __init__(self, fd: int, uri: bytes, method: bytes):
        self.__fd = fd
        self.__c_fd = ctypes.c_int64(self.__fd)
        self.__uri = uri
        self.__method = method
        self.__headers = {}
        self.__queries = {}
        self.__queries_parsed = False
        self.__content_type = ""

    @property
    def uri(self):
        return self.__uri
    
    @property
    def method(self):
        return self.__method
    
    @property
    def content_type(self):
        if self.__content_type == "":
            contenttype = ARCHERLIB.ARCHER_http_request_get_content_type(self.__c_fd)
            if contenttype is None:
                self.__content_type = None
            else:
                self.__content_type = str(contenttype, 'utf-8')
        
        return self.__content_type
    
    def get_header(self, k: str) -> str:
        kl = k.lower()
        if kl in self.__headers:
            return self.__headers[kl]
        c_k = ctypes.c_char_p(k.encode('utf-8'))
        v = ARCHERLIB.ARCHER_http_request_get_header(self.__c_fd, c_k)
        if v is not None and len(v) > 0:
            v = str(v, 'utf-8')
            self.__headers[kl] = v
        return v

    def get_query(self, k: str) -> str:
        if k in self.__queries:
            return self.__queries[k]
        c_k = ctypes.c_char_p(k.encode('utf-8'))
        v = ARCHERLIB.ARCHER_http_request_get_header(self.__c_fd, c_k)
        if v is not None and len(v) > 0:
            v = str(v, 'utf-8')
            self.__queries[k] = v
        return v
    
    def get_queries(self) -> Dict[str, str]:
        if self.__queries_parsed:
            return self.__queries
        
        size = ARCHERLIB.ARCHER_http_request_get_queries_size(self.__c_fd)
        for i in range(0, size):
            c_i = ctypes.c_int(i)
            ks = ARCHERLIB.ARCHER_http_request_get_query_key(self.__c_fd, c_i)
            vs = ARCHERLIB.ARCHER_http_request_get_query_val(self.__c_fd, c_i)
            self.__queries[str(ks, 'utf-8')] = str(vs, 'utf-8')
        self.__queries_parsed = True
        return self.__queries
    
    def get_body(self) -> bytes:
        buf = ctypes.create_string_buffer(2048)
        content = b''
        while True:
            readn = ARCHERLIB.ARCHER_http_request_read_body(self.__c_fd, buf, 2048)
            if readn == 0:
                break
            content += buf.raw[0:readn]
        return content
    
    def read_body(self) -> bytes:
        buf = ctypes.create_string_buffer(2048)
        readn = ARCHERLIB.ARCHER_http_request_read_body(self.__c_fd, buf, 2048)
        if readn == 0:
            return b''
        return buf.raw[0:readn]

class ProHttpResponse():
    
    __fd: int
    __c_fd: int
    __status: int
    __sended: bool

    def __init__(self, fd: int):
        self.__fd = fd
        self.__c_fd = ctypes.c_int64(self.__fd)
        self.__status = 0
        self.__sended = False
    
    def set_status(self, code: int):
        self.__status = code
        c_code = ctypes.c_int(self.__status)
        ARCHERLIB.ARCHER_http_response_set_status(self.__c_fd, c_code)

    def set_header(self, k:str, v:str):
        c_k = ctypes.c_char_p(k.encode('utf-8'))
        c_v = ctypes.c_char_p(v.encode('utf-8'))
        ARCHERLIB.ARCHER_http_response_set_header(self.__c_fd, c_k, c_v)

    def set_content_type(self, type: str):
        c_k = ctypes.c_char_p(b'Content-Type')
        c_v = ctypes.c_char_p(type.encode('utf-8'))
        ARCHERLIB.ARCHER_http_response_set_header(self.__c_fd, c_k, c_v)

    def send_body(self, body: bytes):
        if self.__sended:
            return
        self.__sended = True
        c_body = ctypes.c_char_p(body)
        ARCHERLIB.ARCHER_http_response_send_body(self.__c_fd, c_body, len(body))
    
    def send_chunk_start(self):
        if self.__sended:
            return
        ARCHERLIB.ARCHER_http_response_send_start(self.__c_fd)
    
    def send_chunk(self, chunk: bytes):
        if self.__sended:
            return
        c_chunk = ctypes.c_char_p(chunk)
        ARCHERLIB.ARCHER_http_response_send_chunk(self.__c_fd, c_chunk, len(chunk))
    
    def send_chunk_end(self):
        if self.__sended:
            return
        self.__sended = True
        ARCHERLIB.ARCHER_http_response_send_end(self.__c_fd)
    
    def send_error(self, msg: str):
        content = "<html><head><title>ARCHER-SERVER</title></head><body><h3 style=\"text-align: center; width: 100%\">"+msg+"</h3><body><html>"
        self.set_status(500)
        self.send_body(content.encode('utf-8'))
	

class HttpMessageListenner():
    @abstractmethod
    def handle(self, req: ProHttpRequest, res: ProHttpResponse):
        ''' when http message comes
        '''
        pass
    
    @abstractmethod
    def handle_error(self, err: BaseException):
        ''' when error comes
        '''
        pass

class ProHttpServer():

    __fd: int
    __host: str
    __port: int
    sslctx: SSLContext

    def __init__(self, host:str = "127.0.0.1", port:int = 9617, sslctx: SSLContext = None):
        self.__host = host
        self.__port = port
        self.sslctx = sslctx

    def listen(self, threadnum:int = 0, listenner: HttpMessageListenner = None):

        sslfd = 0
        if self.sslctx is not None:
            if self.sslctx.max_version < self.sslctx.min_version:
                self.sslctx.min_version = self.sslctx.max_version
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
            sslfd = ARCHERLIB.ARCHER_http_server_new_ssl_fd(c_ca, c_crt, c_key, c_en_crt, c_en_key, c_max_ver, c_min_ver)
            if sslfd == 0:
                raise NetError("can not set ssl")
    
        self.__fd = ARCHERLIB.ARCHER_http_server_new_fd(sslfd)
        
        c_fd = ctypes.c_int64(self.__fd)
        c_host = ctypes.c_char_p(self.__host.encode('utf-8'))
        c_port = ctypes.c_int(self.__port)
        c_thread = ctypes.c_int(threadnum)
        c_ssl = ctypes.c_int64(sslfd)

        def handle_message(reqfd: int, resfd: int, uri: bytes, method: bytes):
            if listenner is not None:
                req = ProHttpRequest(reqfd, uri, method)
                res = ProHttpResponse(resfd)
                try:
                    listenner.handle(req, res)
                except Exception as e:
                    try:
                        listenner.handle_error(e)
                    except Exception:
                        pass
                    res.send_error("Internal Server Error")
        
        OnMessageCb = ctypes.CFUNCTYPE(None, ctypes.c_int64, ctypes.c_int64, ctypes.c_char_p, ctypes.c_char_p)
        onMsg = OnMessageCb(handle_message)

        def block_listen():
            try:
                errors = ARCHERLIB.ARCHER_http_server_listen(c_fd, c_host, c_port, c_thread, c_ssl, onMsg)
                if errors is not None and len(errors) > 0:
                    raise NetError(str(errors, 'utf-8'))
            except KeyboardInterrupt:
                self.close()
        
        self.__thread = threading.Thread(target=block_listen)
        self.__thread.start()
    
    def close(self):
        c_fd = ctypes.c_int64(self.__fd)
        ARCHERLIB.ARCHER_http_server_close(c_fd)
