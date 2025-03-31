from abc import abstractmethod
from .fair_lock import FairLock

import threading
import traceback

class ChannelContext:
    __channel: None
    __handler: None
    __prev_ctx: None
    __next_ctx: None

    def __init__(self, channel, handler: None, prev_ctx: None, next_ctx: None):
        self.__channel = channel
        self.__handler = handler
        self.__prev_ctx = prev_ctx
        self.__next_ctx = next_ctx
    
    def __to_bytes(self, data: bytes| str):
        data_bytes = None
        if isinstance(data, bytes):
            data_bytes = data
        elif isinstance(data, str):
            data_bytes = data.encode('utf-8')
        elif isinstance(data, dict) or isinstance(data, list):
            data_bytes = json.dumps(data).encode('utf-8')
        else :
            raise Exception(f"can not send type {type(data)}")

        return data_bytes

    def set_next_ctx(self, next_ctx: None):
        self.__next_ctx = next_ctx

    def set_prev_ctx(self, prev_ctx: None):
        self.__prev_ctx = prev_ctx

    def has_next_handler(self) -> bool:
        return self.__next_ctx != None
    
    def has_prev_handler(self) -> bool:
        return self.__prev_ctx != None

    def to_next_handler_on_connect(self):
        if self.__next_ctx is None:
            raise Exception("can not found next handler")
        self.__next_ctx.handler.on_connect(self.__next_ctx)
    
    def to_next_handler_on_read(self, data: bytes):
        if self.__next_ctx is None:
            raise Exception("can not found next handler")
        self.__next_ctx.handler.on_read(self.__next_ctx, data)
    
    def to_next_handler_on_error(self, e: Exception):
        if self.__next_ctx is None:
            print(str(e))
            stack_trace = traceback.format_exc()
            print(stack_trace)
        else:
            self.__next_ctx.handler.on_error(self.__next_ctx, e)
    
    def to_next_handler_on_close(self):
        if self.__next_ctx is None:
            raise Exception("can not found next handler")
        self.__next_ctx.handler.on_close(self.__next_ctx)

    def to_prev_handler_on_write(self, data: bytes | str):
        data_bytes = self.__to_bytes(data)
        if self.__prev_ctx is None:
            self.__channel.send(data_bytes)
        else:
            self.__prev_ctx.handler.on_write(self.__prev_ctx, data_bytes)

    def send(self, data: bytes | str):
        data_bytes = self.__to_bytes(data)
        self.__handler.on_write(data_bytes)

    def close(self):
        self.__next_ctx = None
        self.__prev_ctx = None
        self.__channel.close()

    @property
    def handler(self):
        return self.__handler
    
    @property
    def channel(self):
        return self.__channel

class Handler:

    @abstractmethod
    def on_connect(self, ctx: ChannelContext):
        ''' 当连接进入时
        '''
        pass

    @abstractmethod
    def on_read(self, ctx: ChannelContext, data: bytes):
        ''' 当有数据被读取时
        '''
        pass
    

    @abstractmethod
    def on_write(self, ctx: ChannelContext, data: bytes):
        ''' 当有数据被读取时
        '''
        pass

    @abstractmethod
    def on_error(self, ctx: ChannelContext, e: Exception):
        ''' 当有错误发生时
        '''
        pass

    @abstractmethod
    def on_close(self, ctx: ChannelContext):
        ''' 当连接关闭时
        '''
        pass



class BaseFrameHandler(Handler):
    
    __data_buf: dict
    __key_lock: threading.Lock

    def __init__(self):
        self.__data_buf = {}
        self.__key_lock = threading.Lock()
        super().__init__()

    def on_connect(self, ctx: ChannelContext):
        if ctx.has_next_handler():
            ctx.to_next_handler_on_connect()

    def on_read(self, ctx: ChannelContext, data: bytes):
        if not ctx.has_next_handler():
            return 
        
        key = ctx.channel.host + str(ctx.channel.port)

        with self.__key_lock:
            if key not in self.__data_buf:
                self.__data_buf[key] = {
                    "lock": FairLock(),
                    "length": -1,
                    "buf": b''
                }
        self.__data_buf[key]["lock"].acquire()
        try:
            self.__data_buf[key]["buf"] = self.__data_buf[key]["buf"] + data
            tot = len(self.__data_buf[key]["buf"])
            
            buf = self.__data_buf[key]["buf"]
            size = self.__data_buf[key]["length"]
            if size == -1:
                if len(buf) < 4:
                    return
                size = int.from_bytes(buf[0:4], byteorder='big', signed=False)
                buf = buf[4:]

            while len(buf) >= size:
                ctx.to_next_handler_on_read(buf[0:size])
                buf = buf[size:]
                if len(buf) < 4:
                    self.__data_buf[key]["length"] = -1
                    self.__data_buf[key]["buf"] = buf
                    return
                size = int.from_bytes(buf[0:4], byteorder='big', signed=False)
                buf = buf[4:]
            
            self.__data_buf[key]["length"] = size
            self.__data_buf[key]["buf"] = buf
        except Exception as e:
            self.on_error(ctx, e)
        finally:
            self.__data_buf[key]["lock"].release()

    def on_error(self, ctx: ChannelContext, e: Exception):
        ctx.to_next_handler_on_error(e)

    def on_close(self, ctx: ChannelContext):
        if ctx.has_next_handler():
            ctx.to_next_handler_on_close()

    def on_write(self, ctx: ChannelContext, data: bytes):
        size = len(data)
        size_bytes = size.to_bytes(4, byteorder='big', signed=False)
        ctx.to_prev_handler_on_write(size_bytes + data)