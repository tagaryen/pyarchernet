import threading, time, os
from .handlers import Handler, BaseFrameHandler, ChannelContext, NetError, HandlerList
from .channel import Channel
from .sm4util import sm4_encrypt_ecb
from .exception import format_exception



class _ResWaiting() :
    condition: threading.Condition
    type: int
    key: bytes
    value: bytes

    def __init__(self, type: int):
        self.condition = threading.Condition()
        self.type = type

    def set_result(self, key:bytes, value: bytes):
        self.key = key
        self.value = value
        with self.condition:
            self.condition.notify_all()

    def wait_for_result(self):
        start = time.time()
        with self.condition:
            self.condition.wait(4)
        if time.time() - start >= 4:
            raise NetError("Waitting for response timeout")

class _RSConnector(Handler):

	# 1  ~  32   for   errors
    _ERROR_HEAD_TYPE = 1
    _ERROR_TYPE_TYPE = 2
    _ERROR_BODY_TYPE = 3
    # 33 ~  64   for   client
    _CLIENT_GET_TYPE = 33
    _CLIENT_SAVE_TYPE = 34
    # 65 ~  96   for   server
    _SERVER_OK_TYPE = 65
    _SERVER_FAIL_TYPE = 66

    host: str
    port: int
    key: str

    connecting: bool
    channel: Channel
    ctx: ChannelContext = None

    condition: threading.Condition

    callback_map = {}

    def __init__(self, host:str, port: int, key: str):
        self.connecting = False
        self.host = host
        self.port = port
        
        self.key = key

        handler_list = HandlerList()
        handler_list.add_handler(BaseFrameHandler())
        handler_list.add_handler(self)
        self.channel = Channel(host, port, handlerlist=handler_list)
        self.ctx = None
        self.condition = threading.Condition()

    def do_connect(self):
        if not self.connecting and not self.channel.active:
            self.connecting = True
            self.channel.connect_async()

            start = time.time()
            with self.condition:
                self.condition.wait(4)
            if time.time() - start >= 4:
                raise NetError("Connect timeout")

    def sendGet(self, key: bytes) -> bytes:
        return self.send(self._CLIENT_GET_TYPE, key, None)

    def sendSave(self, key: bytes, value: bytes):
        self.send(self._CLIENT_SAVE_TYPE, key, value)

    def send(self, type: int, key: bytes, value: bytes) -> bytes:
        if not self.connecting and not self.channel.active:
            self.do_connect()
        data = b'9607'
        nonce = os.urandom(16)
        cipher = sm4_encrypt_ecb(bytes(self.key, 'utf-8'), nonce)
        data += nonce
        data += cipher
        data += type.to_bytes(1, byteorder='big', signed=False)
        data += len(key).to_bytes(2, byteorder='big', signed=False)
        data += key
        if value is not None and type == self._CLIENT_SAVE_TYPE:
            data += value
        
        cb = _ResWaiting(type)
        self.callback_map[nonce.hex()] = cb
        self.on_write(self.ctx, data)
        cb.wait_for_result()
        return cb.value

    def on_connect(self, ctx: ChannelContext):
        self.connecting = True
        self.ctx = ctx
        with self.condition:
            self.condition.notify_all() 

    def on_read(self, ctx: ChannelContext, data: bytes):
        try:
            if b'9607' != data[0:4] :
                raise NetError("Invalid input data")
            nonce = data[4:20]
            type = int.from_bytes(data[52:53], byteorder='big', signed=False)
            cb = self.callback_map[nonce.hex()]
            del self.callback_map[nonce.hex()]
            off = 53
            if type == self._SERVER_OK_TYPE:
                if cb.type == self._CLIENT_SAVE_TYPE:
                    cb.set_result(None, None)
                else:
                    key_len = int.from_bytes(data[off: off+2], byteorder='big', signed=False)
                    off += 2
                    key = data[off: off+key_len]
                    value = data[off+key_len:]
                    cb.set_result(key, value)
            elif type == self._SERVER_FAIL_TYPE:
                raise NetError("Server response failed")
            else:
                raise NetError("Invalid response message type")
        except Exception as e:
            self.on_error(ctx, e)
    
    def on_write(self, ctx: ChannelContext, data: bytes):
        ctx.to_prev_handler_on_write(data)
        
    def on_error(self, ctx: ChannelContext, e: Exception):
        traceback.print_exc(e)
        with self.condition:
            self.condition.notify_all() 

    def on_close(self, ctx: ChannelContext):
        self.connecting = False
        with self.condition:
            self.condition.notify_all() 


class RSClient():
    connector: _RSConnector

    def __init__(self, host:str, port:int, key:str):
        self.connector = _RSConnector(host, port, key)


    def save(self, key:str, value:str):
        self.connector.sendSave(bytes(key, 'utf-8'), bytes(value, 'utf-8'))

    def get(self, key:str)->str:
        return str(self.connector.sendGet(bytes(key, 'utf-8')), 'utf-8')