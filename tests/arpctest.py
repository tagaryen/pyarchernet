from pyarchernet import ARPCClient, ARPCServer, AbstractUrlMatcher, SSLContext
import threading
import time
import io


class ServerURlA(AbstractUrlMatcher):

    def on_message(self, msg: dict) -> dict:
        print("收到客户端消息 {}".format(msg))
        return {'c': "python send"}

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
server.add_url_matcher("/你好", ServerURlA())
server.listen_async("127.0.0.1", 9067)

time.sleep(1)

# with open('tests/gm_cert/server.crt', 'r', encoding='utf-8') as file:
#     cli_crt = file.read()
# with open('tests/gm_cert/server.key', 'r', encoding='utf-8') as file:
#     cli_key = file.read()
# with open('tests/gm_cert/server_en.crt', 'r', encoding='utf-8') as file:
#     cli_en_crt = file.read()
# with open('tests/gm_cert/server_en.key', 'r', encoding='utf-8') as file:
#     cli_en_key = file.read()

# sslctx1 = SSLContext(is_client_mode = True)
# sslctx1.verify_peer = False
# sslctx1.ca = ca
# sslctx1.crt = cli_crt
# sslctx1.key = cli_key
# sslctx1.en_crt = cli_en_crt
# sslctx1.en_key = cli_en_key

# cli = ARPCClient("127.0.0.1", 9067, sslctx = sslctx1)
# res0 = cli.call("/你好", {'a':'你好url'})
# print("收到服务端消息 {}".format(res0))
time.sleep(10)

# cli.close()
server.close()