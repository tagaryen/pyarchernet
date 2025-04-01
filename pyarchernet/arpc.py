import json, traceback, threading, time
from typing import Any, Callable
from abc import abstractmethod
from .handlerlist import HandlerList
from .handlers import Handler, BaseFrameHandler, ChannelContext
from .channel import Channel
from .server_channel import ServerChannel
from .sslcontext import SSLContext

def _check_type_error(t):
    if t is None:
        return True
    if t is type :
        return True
    if t is int :
        return True
    if t is float :
        return True
    if t is complex :
        return True
    if t is bytes :
        return True
    if t is str :
        return True
    if t is tuple :
        return True
    if t is list :
        return True
    if t is dict :
        return True
    if t is set :
        return True
    return False

ARPC_TIMEOUT = 2

class ARPCClientMessageListenner:
    __lock: threading.Lock
    __cond: threading.Condition
    __val: None
    
    def __init__(self, send_type: type, receive_type: type):
        if _check_type_error(send_type) or _check_type_error(receive_type):
            raise Exception("send_type and return must be class types")
        self.__send_type = send_type
        self.__receive_type = receive_type
        self.__lock = None
        self.__cond = None
        self.__val = None
        self.__callback = None

    def set_callback(self, callback: Callable):
        self.__callback = callback

    def set_sync(self, lock):
        self.__lock = lock
        self.__cond = threading.Condition(self.__lock)
    
    def is_sync(self) -> bool:
        return self.__lock is not None

    def do_wait(self):
        if self.__lock is None or self.__val is not None:
            return 
        start = int(time.time())
        with self.__lock:
            self.__cond.wait(ARPC_TIMEOUT)
        if start + ARPC_TIMEOUT <= int(time.time()):
            raise Exception("connect timeout")

    def unset_sync(self, val):
        with self.__lock:
            self.__cond.notify_all()
        self.__lock = None
        self.__cond = None
        self.__val = val
    
    def get_val(self):
        val = self.__val
        self.__val = None
        return val

    @property
    def receive_type(self):
        return self.__receive_type

    @property
    def send_type(self):
        return self.__send_type
    
    @property
    def callback(self)->Callable:
        return self.__callback

class ARPCServerMessageListenner:

    def __init__(self, send_type: type, receive_type: type):
        if _check_type_error(send_type) or _check_type_error(receive_type):
            raise Exception("send_type and return must be class types")
        self.__send_type = send_type
        self.__receive_type = receive_type

    @property
    def receive_type(self):
        return self.__receive_type

    @property
    def send_type(self):
        return self.__send_type
    
    @abstractmethod
    def handle_receive_and_gen_send(self, return_type_val)->Any:
        '''implements this method to handle receive message
           then generate a send message, or return None to avoid send back
        '''
        pass

class _ARPCClientHandler(Handler):

    receive_listenner: dict[str, ARPCClientMessageListenner]
    send_listenner: dict[str, ARPCClientMessageListenner]
    error_cb: None
    client: None


    def __init__(self, connect_message = None, error_cb: Callable = None):
        if connect_message is not None and _check_type_error(type(connect_message)):
            raise Exception(f"invalid on connect message type {type(connect_message)}")
        self.connect_message = connect_message
        self.receive_listenner = {}
        self.send_listenner = {}
        self.error_cb = error_cb

    def on_connect(self, ctx: ChannelContext):
        self.client.set_channel_context(ctx)
        if self.connect_message is not None:
            name = type(self.connect_message).__name__.lower().encode('utf-8')
            name_len = len(name).to_bytes(2, byteorder="big", signed=False)
            data = json.dumps(self.connect_message.__dict__).encode('utf-8')
            ctx.to_prev_handler_on_write(name_len + name + data)
    
    def on_read(self, ctx: ChannelContext, data: bytes):
        name_len = int.from_bytes(data[0:2], byteorder="big", signed=False)
        name = str(data[2:2+name_len], 'utf-8')
        data = str(data[2+name_len:], 'utf-8')
        if name not in self.receive_listenner:
            self.on_error(ctx, Exception(f"can not found message listenner for {name}"))
            return 
        listenner = self.receive_listenner[name]
        T = listenner.receive_type
        ins = T()
        ins.__dict__ = json.loads(data)
        if listenner.is_sync():
            listenner.unset_sync(ins)
        else:
            callback = listenner.callback
            if callback is not None:
                callback(ins)

    def do_send(self, ctx: ChannelContext, send_ins):
        name = type(send_ins).__name__.lower()
        if name not in self.send_listenner:
            raise Exception(f"type {name} can not be found")
        name = name.encode('utf-8')
        name_len = len(name).to_bytes(2, byteorder="big", signed=False)
        data = json.dumps(send_ins.__dict__).encode('utf-8')
        ctx.to_prev_handler_on_write(name_len+name+data)

    def on_error(self, ctx: ChannelContext, e: Exception):
        if self.error_cb is None:
            print(str(e))
            stack_trace = traceback.format_exc()
            print(stack_trace)
        else:
            self.error_cb(e)



class _ARPCServerHandler(Handler):

    receive_listenner: dict[str, ARPCServerMessageListenner]
    send_listenner: dict[str, ARPCServerMessageListenner]
    error_cb: None

    def __init__(self, error_cb: Callable = None):
        self.error_cb = error_cb
        self.receive_listenner = {}
        self.send_listenner = {}

    def on_read(self, ctx: ChannelContext, data: bytes):
        name_len = int.from_bytes(data[0:2], byteorder="big", signed=False)
        name = str(data[2:name_len+2], 'utf-8')
        data = str(data[2+name_len:], 'utf-8')
        if name not in self.receive_listenner:
            self.on_error(ctx, Exception(f"can not found message listenner for {name}"))
            return 
        listenner = self.receive_listenner[name]
        T = listenner.receive_type
        ins = T()
        ins.__dict__ = json.loads(data)
        ret = listenner.handle_receive_and_gen_send(ins)
        if ret is None:
            return 
        name = type(ret).__name__.lower()
        if name not in self.send_listenner:
            self.on_error(ctx, Exception(f"can not found message type {name}"))
            return 
        name = name.encode('utf-8')
        name_len = len(name).to_bytes(2, byteorder="big", signed=False)
        data = json.dumps(ret.__dict__).encode('utf-8')
        ctx.to_prev_handler_on_write(name_len + name + data)

    def on_error(self, ctx: ChannelContext, e: Exception):
        if self.error_cb is None:
            print(str(e))
            stack_trace = traceback.format_exc()
            print(stack_trace)
        else:
            self.error_cb(e)
    

class ARPCClient:
    __ctx: ChannelContext

    def __init__(self, host = "127.0.0.1", port = 9607, sslctx: SSLContext = None):
        handlerlist = HandlerList()
        handlerlist.add_handler(BaseFrameHandler())
        self.__handler = _ARPCClientHandler()
        self.__handler.client = self
        handlerlist.add_handler(self.__handler)
        
        self.__channel = Channel(host, port, sslctx=sslctx, handlerlist=handlerlist)
        self.__channel_active_lock = threading.Lock()
        self.__channel_active_cond = threading.Condition(self.__channel_active_lock)
        self.__ctx = None
    
    def __check_connection(self):
        if not self.__channel.active:
            self.__channel.connect()
            start = int(time.time())
            with self.__channel_active_lock:
                self.__channel_active_cond.wait(ARPC_TIMEOUT)
            
            if start + ARPC_TIMEOUT <= int(time.time()):
                raise Exception("connect timeout")

    def set_channel_context(self, ctx: ChannelContext):
        self.__ctx = ctx
        with self.__channel_active_lock:
            self.__channel_active_cond.notify_all()

    def set_connect_message(self, connect_message = None):
        self.__handler.connect_message = connect_message
    
    def set_error_cb(self, error_cb: Callable = None):
        self.__handler.error_cb = error_cb

    def add_message_listenner(self, listenner: ARPCClientMessageListenner):
        if not isinstance(listenner, ARPCClientMessageListenner):
            raise Exception(f"listener must be type {ARPCClientMessageListenner}, but got {type(listenner)}")
        self.__handler.receive_listenner[listenner.receive_type.__name__.lower()] = listenner
        self.__handler.send_listenner[listenner.send_type.__name__.lower()] = listenner
    
    def call_remote_async(self, val, callback: Callable):
        type_name = type(val).__name__.lower()
        if type_name not in self.__handler.send_listenner:
            raise Exception(f"type {type_name} can not be found")
        self.__check_connection()
        listenner = self.__handler.send_listenner[type_name]
        listenner.set_callback(callback)
        self.__handler.do_send(self.__ctx, val)

    def call_remote(self, val):
        type_name = type(val).__name__.lower()
        if type_name not in self.__handler.send_listenner:
            raise Exception(f"type {type_name} can not be found")
        self.__check_connection()
        listenner = self.__handler.send_listenner[type_name]
        listenner.set_sync(threading.Lock())
        self.__handler.do_send(self.__ctx, val)
        listenner.do_wait()
        ret = listenner.get_val()
        if ret is None:
            raise Exception("can not get response")
        return ret
    
    def close(self):
        self.__channel.close()

class ARPCServer:
    def __init__(self, host = "127.0.0.1", port = 9607, sslctx: SSLContext = None):
        handlerlist = HandlerList()
        handlerlist.add_handler(BaseFrameHandler())
        self.__handler = _ARPCServerHandler()
        handlerlist.add_handler(self.__handler)
        
        self.__server = ServerChannel(host, port, sslctx=sslctx, handlerlist=handlerlist)

    def start(self):
        self.__server.start_listen()

    def close(self):
        self.__server.close()

    def set_error_cb(self, error_cb: Callable = None):
        self.__handler.error_cb = error_cb

    def add_message_listenner(self, listenner: ARPCServerMessageListenner):
        if not isinstance(listenner, ARPCServerMessageListenner):
            raise Exception(f"listener must be type {ARPCServerMessageListenner}, but got {type(listenner)}")
        self.__handler.receive_listenner[listenner.receive_type.__name__.lower()] = listenner
        self.__handler.send_listenner[listenner.send_type.__name__.lower()] = listenner
    