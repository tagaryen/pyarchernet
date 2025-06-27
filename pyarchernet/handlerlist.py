
from .handlers import Handler, ChannelContext, NetError

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
        self.__handlers.append(handler)

    def insert_handler(self, index: int, handler: Handler):
        if index > len(self.__handlers) or index < 0:
            raise NetError("index out of bound")
        if index == len(self.__handlers):
            self.add_handler(handler)
        self.__handlers.insert(index, handler)

    def remove_handler(self, index: int):
        if index > len(self.__handlers) or index < 0:
            raise NetError("index out of bound")
        del self.__handlers[index]


