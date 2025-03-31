from pyarchernet import ARPCClient, ARPCServer, ARPCClientMessageListenner, ARPCServerMessageListenner, SSLContext
import threading
import time
import io

class MessageA:
    a: str

class MessageB:
    b: str


class MessageC:
    c: str

class ClientMsgLis(ARPCClientMessageListenner):

    def __init__(self):
        super().__init__(MessageB, MessageA)

class ServerMsgLis(ARPCServerMessageListenner):

    def __init__(self):
        super().__init__(MessageA, MessageB)

    def do_send(self):
        rec = MessageA()
        rec.a = "naosiaoc@assa.com"
        print("server send a = naosiaoc@assa.com", flush=True)
        return rec

    def on_message(self, val: MessageB):
        print(f"server recv b = {val.b}",flush=True)

with open('tests/gm_cert/ca.crt', 'r', encoding='utf-8') as file:
    ca = file.read()
with open('tests/gm_cert/server.crt', 'r', encoding='utf-8') as file:
    crt = file.read()
with open('tests/gm_cert/server.key', 'r', encoding='utf-8') as file:
    key = file.read()
with open('tests/gm_cert/server_en.crt', 'r', encoding='utf-8') as file:
    en_crt = file.read()
with open('tests/gm_cert/server_en.key', 'r', encoding='utf-8') as file:
    en_key = file.read()

sslctx = SSLContext(is_client_mode = False)
sslctx.ca = ca
sslctx.crt = crt
sslctx.key = key
sslctx.en_crt = en_crt
sslctx.en_key = en_key


server = ARPCServer(sslctx = sslctx)
server.add_message_listenner(ServerMsgLis())
server.start()

time.sleep(1)

with open('tests/gm_cert/server.crt', 'r', encoding='utf-8') as file:
    cli_crt = file.read()
with open('tests/gm_cert/server.key', 'r', encoding='utf-8') as file:
    cli_key = file.read()
with open('tests/gm_cert/server_en.crt', 'r', encoding='utf-8') as file:
    cli_en_crt = file.read()
with open('tests/gm_cert/server_en.key', 'r', encoding='utf-8') as file:
    cli_en_key = file.read()

# sslctx1 = SSLContext(is_client_mode = True)
# sslctx1.verify_peer = False
# sslctx1.ca = ca
# sslctx1.crt = cli_crt
# sslctx1.key = cli_key
# sslctx1.en_crt = cli_en_crt
# sslctx1.en_key = cli_en_key

# cli = ARPCClient(sslctx = sslctx1)
# cli.add_message_listenner(ClientMsgLis())

# se = MessageB()
# se.b = "xuyi haoshuai"
# # se.age = 18

# ret = cli.call_remote(se)

# print(ret.__dict__, flush=True)

# time.sleep(2)

# cli.close()
# server.close()