import json, traceback, threading, time, os
from typing import Any, Callable
from abc import abstractmethod
from .handlers import Handler, BaseFrameHandler, ChannelContext, NetError, HandlerList
from .channel import Channel
from .server_channel import ServerChannel
from .sslcontext import SSLContext

NOTFOUND = b'\0\0\0\0NOTFOUND'
NOTFOUND_LEN = len(NOTFOUND)

def _check_is_not_found(input: bytes):
    if input is None or len(input) != NOTFOUND_LEN:
        return False
    for i in range(0, NOTFOUND_LEN):
        if NOTFOUND[i] != input[i]:
            return False
    return True

class AbstractUrlMatcher():

    @abstractmethod
    def on_message(self, msg: dict) -> dict:
        '''
        收到对方的消息时
        '''
        pass


class _ARPCHandler(Handler):
    
    __url_map: dict

    __ex_cb: Callable

    def __init__(self):
        self.__url_map = {}
        self.__ex_cb = None
        super().__init__()
        
    def on_error(self, ctx: ChannelContext, e: Exception):
        if self.__ex_cb is not None:
            self.__ex_cb(e)
        else:
            traceback.print_exception(e)
    
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
    
    def __send_not_found(self, ctx: ChannelContext):
        data = NOTFOUND_LEN.to_bytes(2, byteorder="big", signed=False) + NOTFOUND
        ctx.to_prev_handler_on_write(data)

    def on_read(self, ctx: ChannelContext, data: bytes):
        try: 
            off_s, off_e = 0, 2
            url_len = int.from_bytes(data[off_s:off_e], byteorder="big", signed=False)
            off_s, off_e = off_e, off_e + url_len
            url = data[off_s:off_e]
            if _check_is_not_found(url):
                super().on_error(ctx, NetError("Client send not found"))
                return 
            url = str(url, 'utf-8')
            off_s = off_e
            matcher = super().get_url_matcher(url)
            if matcher is None:
                super().on_error(ctx, NetError("Can not found matcher for url {}".format(url)))
                self.__send_not_found(ctx)
            else:
                res = matcher.on_message(json.loads(str(data[off_s:], 'utf-8')))
                res = {} if res is None else res
                res_bs = data[:2+url_len] + bytes(json.dumps(res), 'utf-8')
                ctx.to_prev_handler_on_write(res_bs)
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

    def listen_async(self, host: str, port: int):
        self.__do_listen(host, port, handler=self.__handler, is_async=True)

    def listen(self, host: str, port: int):
        self.__do_listen(host, port, handler=self.__handler, is_async=False)
    
    def __do_listen(self, host: str, port: int, handler: _ARPCServerHandler, is_async: bool):
        if not isinstance(host, str):
            raise ValueError("host must be a int")
        if not isinstance(port, int):
            raise ValueError("port must be a int")
        handlerList = HandlerList()
        handlerList.add_handler(BaseFrameHandler())
        handlerList.add_handler(self.__handler)
        self.__server = ServerChannel(host, port, self.__threads, self.__sslctx, handlerlist=handlerList)
        if is_async:
            self.__server.listen_async()
        else:
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

    __cb_map: dict

    def __init__(self, active_cb: Callable):
        self.__cb = active_cb
        self.__cb_map = {}
        super().__init__()

    def on_connect(self, ctx: ChannelContext):
        self.__cb(ctx, True)

    def on_read(self, ctx: ChannelContext, data: bytes):
        try: 
            off_s, off_e = 0, 2
            url_len = int.from_bytes(data[off_s:off_e], byteorder="big", signed=False)
            off_s, off_e = off_e, url_len + off_e
            url = data[off_s:off_e]
            if _check_is_not_found(url):
                super().on_error(ctx, NetError("Server send not found"))
                return 
            url = str(url, 'utf-8')
            data = str(data[off_e:], 'utf-8')
            cb = self.get_url_cb(url)
            if cb is None:
                super().on_error(ctx, NetError("Can not found matcher for url {}".format(url)))
            else:
                cb(json.loads(data))
        except Exception as e:
            super().on_error(ctx, e)

    def on_close(self, ctx: ChannelContext):
        self.__cb(ctx, False)

    def get_url_cb(self, url: str) -> Callable:
        if url not in self.__cb_map:
            return None
        return self.__cb_map[url]

    def add_url_cb(self, url: str, cb: Callable):
        self.__cb_map[url] = cb


class ARPCClient():
    
    __TIMEOUT = 2

    __host: str
    __port: int
    __active: bool
    __ctx: SSLContext
    __ctx_lock: threading.Lock
    __ctx_cnd: threading.Condition

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
        self.__active = False
        self.__ctx_lock = threading.Lock()
        self.__ctx_cnd = threading.Condition(self.__ctx_lock)

        def client_connected_cb(ctx: ChannelContext, active: bool):
            self.__active = active
            self.__ctx = ctx
            with self.__ctx_lock:
                self.__ctx_cnd.notify()

        self.__handler = _ARPCClientHandler(client_connected_cb)
    
    def __do_connect(self):
        if self.__active:
            return
        handlerList = HandlerList()
        handlerList.add_handler(BaseFrameHandler())
        handlerList.add_handler(self.__handler)
        self.__channel = Channel(self.__host, self.__port, sslctx=self.__sslctx, handlerlist=handlerList)
        self.__channel.connect_async()
        
        start = int(time.time())
        with self.__ctx_lock:
            self.__ctx_cnd.wait(ARPCClient.__TIMEOUT)
        if start + ARPCClient.__TIMEOUT <= int(time.time()):
            raise NetError("Connect timeout")
    
    def call(self, url: str, data: dict) -> dict:
        if not isinstance(url, str):
            raise ValueError("url must be a int")
        if not isinstance(data, dict):
            raise ValueError("data must be dict")
        self.__do_connect()
        msg = {'res': None}
        msg_lock = threading.Lock()
        msg_cnd = threading.Condition(msg_lock)
        def msg_cb(res: dict):
            msg['res'] = res
            with msg_lock:
                msg_cnd.notify_all()
        self.call_async(url, data, msg_cb)
        start = int(time.time())
        with msg_lock:
            msg_cnd.wait(ARPCClient.__TIMEOUT)
        if start + ARPCClient.__TIMEOUT <= int(time.time()):
            raise NetError("Read timeout")
        if msg['res'] == None:
            raise NetError("Can not get response")
        return msg['res']
    
    def call_async(self, url: str, data: dict, msg_callback: Callable):
        if not isinstance(url, str):
            raise ValueError("url must be a int")
        if not isinstance(data, dict):
            raise ValueError("data must be dict")
        if msg_callback is not None and not isinstance(msg_callback, Callable):
            raise ValueError("msg_callback must be Callable")
        self.__do_connect()
        self.__handler.add_url_cb(url, msg_callback)
        res = b'{}' if data is None else json.dumps(data)
        url_bs = bytes(url, 'utf-8')
        res_bs = len(url_bs).to_bytes(2, byteorder="big", signed=False) + url_bs + bytes(res, 'utf-8')
        self.__ctx.to_prev_handler_on_write(res_bs)

    def close(self):
        self.__channel.close()