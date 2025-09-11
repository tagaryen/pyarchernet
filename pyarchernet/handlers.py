from abc import abstractmethod
from .fair_lock import FairLock

import threading, traceback, json

class NetError(RuntimeError):
    def __init__(self, *args):
        super().__init__(*args)


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
    
    def __error(self, msg: str):
        if self.__handler is None:
            print("ERROR: {}".format(msg))
        else:
            self.__handler.on_error(self, NetError(msg))

    def __to_bytes(self, data: bytes| str):
        data_bytes = None
        if isinstance(data, bytes):
            data_bytes = data
        elif isinstance(data, str):
            data_bytes = data.encode('utf-8')
        elif isinstance(data, dict) or isinstance(data, list):
            data_bytes = json.dumps(data).encode('utf-8')
        else :
            self.__error("can not send type {}".format(type(data)))

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
            self.__error("can not found next handler")
        self.__next_ctx.handler.on_connect(self.__next_ctx)
    
    def to_next_handler_on_read(self, data: bytes):
        if self.__next_ctx is None:
            self.__error("can not found next handler")
        else:
            self.__next_ctx.handler.on_read(self.__next_ctx, data)
    
    def to_next_handler_on_error(self, e: Exception):
        if self.__next_ctx is None:
            traceback.print_exception(e)
        else:
            self.__next_ctx.handler.on_error(self.__next_ctx, e)
    
    def to_next_handler_on_close(self):
        if self.__next_ctx is None:
            self.__error("can not found next handler")
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

    def __init__(self):
        self.__data_buf = {}
        super().__init__()

    def on_connect(self, ctx: ChannelContext):
        if ctx.has_next_handler():
            ctx.to_next_handler_on_connect()

    def on_read(self, ctx: ChannelContext, data: bytes):
        if not ctx.has_next_handler():
            return 
        
        key = ctx.channel.host + str(ctx.channel.port)

        if key not in self.__data_buf:
            self.__data_buf[key] = {
                "length": -1,
                "buf": b''
            }
        try:
            self.__data_buf[key]["buf"] = self.__data_buf[key]["buf"] + data
            
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

    def on_error(self, ctx: ChannelContext, e: Exception):
        ctx.to_next_handler_on_error(e)

    def on_close(self, ctx: ChannelContext):
        if ctx.has_next_handler():
            ctx.to_next_handler_on_close()

    def on_write(self, ctx: ChannelContext, data: bytes):
        size = len(data)
        size_bytes = size.to_bytes(4, byteorder='big', signed=False)
        ctx.to_prev_handler_on_write(size_bytes + data)


class HandlerList:
    __handlers: list[Handler]
    __ctx_dict: dict

    def __init__(self):
        self.__handlers = []
        self.__ctx_dict = {}

    def find_channel_contxet(self, channel)->ChannelContext:
        key = channel.host + str(channel.port)
        if key in self.__ctx_dict:
            return self.__ctx_dict[key]
        
        size = len(self.__handlers)
        if size == 0:
            return None
        head_ctx = ChannelContext(channel, self.__handlers[0], None, None)
        prev_ctx = head_ctx
        if size > 1:    
            for i in range(1, size):
                cur_ctx = ChannelContext(channel, self.__handlers[i], prev_ctx=prev_ctx, next_ctx=None)
                prev_ctx.set_next_ctx(cur_ctx)
                prev_ctx = cur_ctx
        return head_ctx

    @property
    def handlers(self) -> list[Handler]:
        return self.__handlers

    def add_handler(self, handler: Handler):
        if handler is None:
            return 
        if not isinstance(handler, Handler):
            raise ValueError("handler must be Handler")
        self.__handlers.append(handler)

    def insert_handler(self, index: int, handler: Handler):
        if not isinstance(index, int):
            raise ValueError("index must be int")
        if index > len(self.__handlers) or index < 0:
            raise ValueError("index out of bound")
        if handler is None or not isinstance(handler, Handler):
            raise ValueError("handler must be Handler")
        if index == len(self.__handlers):
            self.add_handler(handler)
        self.__handlers.insert(index, handler)

    def remove_handler(self, index: int):
        if not isinstance(index, int):
            raise ValueError("index must be int")
        if index > len(self.__handlers) or index < 0:
            raise ValueError("index out of bound")
        del self.__handlers[index]