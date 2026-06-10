import json, threading, time, os
from typing import Callable, Dict
from abc import abstractmethod
from .handlers import Handler, ChannelContext, NetError, HandlerList
from .channel import Channel
from .server_channel import ServerChannel
from .sslcontext import SSLContext
from .exception import format_exception

NOTFOUND = b'\0\0\0\0NOTFOUND'
NOTFOUND_LEN = len(NOTFOUND)
PARAMERR = b'\0\0\0\0PARAMERR'
PARAMERR_LEN = len(PARAMERR)

def _check_is_not_found(input: bytes):
    if input is None or len(input) != NOTFOUND_LEN:
        return False
    for i in range(0, NOTFOUND_LEN):
        if NOTFOUND[i] != input[i]:
            return False
    return True

def _check_is_param_err(input: bytes):
    if input is None or len(input) != PARAMERR_LEN:
        return False
    for i in range(0, PARAMERR_LEN):
        if PARAMERR[i] != input[i]:
            return False
    return True

class AbstractUrlMatcher():

    @abstractmethod
    def on_message(self, msg: Dict) -> Dict:
        '''
        收到对方的消息时
        '''
        pass


class _ARPCHandler(Handler):
    
    __url_map: Dict
    __ex_cb: Callable

    def __init__(self):
        self.__url_map = {}
        self.__ex_cb = None
        super().__init__()
        
    def on_error(self, ctx: ChannelContext, e: Exception):
        if self.__ex_cb is not None:
            self.__ex_cb(e)
        else:
            format_exception(e)
    
    def add_url_matcher(self, url: str, matcher: AbstractUrlMatcher):
        self.__url_map[url] = matcher
    
    def get_url_matcher(self, url: str) -> AbstractUrlMatcher:
        if url not in self.__url_map:
            return None
        return self.__url_map[url]

    @property
    def exception_handler(self) -> Callable:
        return self.__ex_cb

    @exception_handler.setter
    def exception_handler(self, ex_cb: Callable):
        self.__ex_cb = ex_cb




class _ARPCServerHandler(_ARPCHandler):

    def __init__(self):
        super().__init__()
    
    def __send_not_found(self, ctx: ChannelContext, nonce: bytes):
        data = nonce + NOTFOUND_LEN.to_bytes(2, byteorder="big", signed=False) + NOTFOUND
        res = len(data).to_bytes(byteorder='big', length=4, signed=False) + data
        ctx.to_prev_handler_on_write(res)
    
    def __send_param_err(self, ctx: ChannelContext, nonce: bytes):
        data = nonce + PARAMERR_LEN.to_bytes(2, byteorder="big", signed=False) + PARAMERR
        res = len(data).to_bytes(byteorder='big', length=4, signed=False) + data
        ctx.to_prev_handler_on_write(res)

    def on_read(self, ctx: ChannelContext):
        try: 
            while True:
                total_len = ctx.read_int32()
                if total_len < 0:
                    return
                data = ctx.read_len(total_len)
                nonce = data[:16]
                off = 16
                url_len = int.from_bytes(data[off:off+2], byteorder='big', signed=False)
                off += 2
                url = data[off:off+url_len]
                off += url_len
                matcher = super().get_url_matcher(str(url, 'utf-8'))
                if matcher is None:
                    super().on_error(ctx, NetError("Can not found matcher for url {}".format(str(url, 'utf-8'))))
                    self.__send_not_found(ctx, nonce)
                else:
                    try:
                        res = matcher.on_message(json.loads(str(data[off:], 'utf-8')))
                        res = {} if res is None else res
                        res_bs = data[:off] + bytes(json.dumps(res), 'utf-8')
                        ctx.to_prev_handler_on_write(len(res_bs).to_bytes(byteorder='big', length=4, signed=False)+res_bs)
                    except Exception:
                        self.__send_param_err(ctx, nonce)
        except Exception as e:
            super().on_error(ctx, e)
        


class ARPCServer():
    def __init__(self, threads: int = 0, sslctx: SSLContext = None):
        if not isinstance(threads, int):
            raise ValueError("Threads must be a int")
        if sslctx is not None and not isinstance(sslctx, SSLContext):
            raise ValueError("Sslctx must be SSLContext")
        if threads > 128:
            threads = 128
        if threads < 0:
            threads = 0
        self.__threads = threads
        self.__sslctx = sslctx
        self.__handler =  _ARPCServerHandler()

    def listen(self, host: str, port: int):
        if not isinstance(host, str):
            raise ValueError("host must be a int")
        if not isinstance(port, int):
            raise ValueError("port must be a int")
        handlerList = HandlerList()
        handlerList.add_handler(self.__handler)
        self.__server = ServerChannel(host, port, self.__threads, self.__sslctx, handlerlist=handlerList)
        self.__server.listen()

    def close(self):
        self.__server.close()

    def add_url_matcher(self, url: str, matcher: AbstractUrlMatcher):
        if not isinstance(url, str):
            raise ValueError("url must be a int")
        if not isinstance(matcher, AbstractUrlMatcher):
            raise ValueError("matcher must be AbstractUrlMatcher")
        self.__handler.add_url_matcher(url, matcher=matcher)

class _ARPCClientHandler(_ARPCHandler):

    __cb_map: Dict
    __ctx_cnd = threading.Condition()
    __cb: Callable

    def __init__(self, cb: Callable):
        self.__cb_map = {}
        self.__ctx_cnd = threading.Condition()
        self.__cb = cb
        super().__init__()

    def on_connect(self, ctx: ChannelContext):
        self.__cb(ctx)
        with self.__ctx_cnd:
            self.__ctx_cnd.notify_all()

    def on_read(self, ctx: ChannelContext):
        while True:
            try: 
                total_len = ctx.read_int32()
                if total_len <= 0:
                    return 
                data = ctx.read_len(total_len)
                nonce = data[:16]
                off = 16
                url_len = int.from_bytes(data[off:off+2], byteorder='big', signed=False)
                off += 2
                url = data[off:off+url_len]
                off += url_len
                cb = self.get_url_cb(nonce.hex())
                if cb is None:
                    super().on_error(ctx, NetError("Invalid nonce"))
                else:
                    if _check_is_not_found(url):
                        cb(None, NetError("Server url not found"))
                    elif _check_is_param_err(url):
                        cb(None, NetError("Server param error"))
                    else:
                        cb(json.loads(str(data[off:], 'utf-8')), None)
            except Exception as e:
                super().on_error(ctx, e)

    def on_close(self, ctx: ChannelContext):
        self.__cb(ctx)

    def get_url_cb(self, nonce: str) -> Callable:
        if nonce not in self.__cb_map:
            return None
        cb = self.__cb_map[nonce]
        del self.__cb_map[nonce]
        return cb

    def add_url_cb(self, nonce: str, cb: Callable):
        self.__cb_map[nonce] = cb
    
    def wait_for_connect(self):
        start = time.time()
        with self.__ctx_cnd:
            self.__ctx_cnd.wait(4)
        if time.time() - start >= 4:
            raise NetError("Connect timeout")

class _ResWaiting() :
    condition: threading.Condition
    res: Dict
    ex: Exception

    def __init__(self):
        self.condition = threading.Condition()
        self.res = None

    def set_result(self, res: Dict, ex: Exception):
        self.res = res
        self.ex = ex
        with self.condition:
            self.condition.notify()

    def wait_for_result(self):
        start = time.time()
        with self.condition:
            self.condition.wait(3)
        if time.time() - start >= 3:
            raise NetError("Waitting for response timeout")



class ARPCClient():
    
    __TIMEOUT = 3

    __host: str
    __port: int
    __sslctx: SSLContext
    __ctx: ChannelContext

    def __init__(self, host: str, port: int, sslctx: SSLContext = None):
        if not isinstance(host, str):
            raise ValueError("host must be a int")
        if not isinstance(port, int):
            raise ValueError("port must be int")
        if sslctx is not None and not isinstance(sslctx, SSLContext):
            raise ValueError("sslctx must be SSLContext")
        self.__host = host
        self.__port = port
        self.__sslctx = sslctx

        def connect_cb(ctx: ChannelContext):
            self.__ctx = ctx
        self.__handler = _ARPCClientHandler(connect_cb)
        handlerList = HandlerList()
        handlerList.add_handler(self.__handler)
        self.__channel = Channel(self.__host, self.__port, sslctx=self.__sslctx, handlerlist=handlerList)
    
    def __do_connect(self):
        if not self.__channel.active:
            self.__channel.connect()
            self.__handler.wait_for_connect()
    
    def call(self, url: str, data: Dict) -> Dict:
        if not isinstance(url, str):
            raise ValueError("url must be a int")
        if not isinstance(data, Dict):
            raise ValueError("data must be Dict")
        self.__do_connect()
        waiting = _ResWaiting()
        def msg_cb(res: Dict, ex: Exception):
            waiting.set_result(res, ex)
        
        nonce = os.urandom(16)
        url_bs = url.encode('utf-8')
        data_bs = b'{}' if data is None else json.dumps(data, ensure_ascii=False).encode('utf-8')
        
        self.__handler.add_url_cb(nonce.hex(), msg_cb)

        res_bs = nonce + len(url_bs).to_bytes(2, byteorder="big", signed=False) + url_bs + data_bs
        self.__ctx.to_prev_handler_on_write(len(res_bs).to_bytes(4, byteorder="big", signed=False) + res_bs)

        if waiting.res is not None:
            return waiting.res
        waiting.wait_for_result()
        if waiting.ex is not None:
            raise waiting.ex
        if waiting.res is None:
            raise NetError("Can not get response")
        return waiting.res

    def close(self):
        self.__channel.close()