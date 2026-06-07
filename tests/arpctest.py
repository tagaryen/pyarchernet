from archernet import ARPCServer, ARPCClient, AbstractUrlMatcher, SSLContext
import time
from typing import Dict


class ServerURlA(AbstractUrlMatcher):

    def on_message(self, msg: Dict) -> Dict:
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


server = ARPCServer()
server.add_url_matcher("/你好", ServerURlA())
server.listen_async("127.0.0.1", 9067)

time.sleep(1)

with open('tests/gm_cert/cli.crt', 'r', encoding='utf-8') as file:
    cli_crt = file.read()
with open('tests/gm_cert/cli.key', 'r', encoding='utf-8') as file:
    cli_key = file.read()
with open('tests/gm_cert/cli_en.crt', 'r', encoding='utf-8') as file:
    cli_en_crt = file.read()
with open('tests/gm_cert/cli_en.key', 'r', encoding='utf-8') as file:
    cli_en_key = file.read()

sslctx1 = SSLContext(is_client_mode = True)
sslctx1.verify_peer = False
sslctx1.ca = ca
sslctx1.crt = cli_crt
sslctx1.key = cli_key
sslctx1.en_crt = cli_en_crt
sslctx1.en_key = cli_en_key

cli = ARPCClient("127.0.0.1", 9067)
res0 = cli.call("/你好", {'a':'你好url'})
res1 = cli.call("/你好", {'b':'你好b'})
print("收到服务端消息1 {}".format(res0))
print("收到服务端消息2 {}".format(res1))
time.sleep(10)

# cli.close()
server.close()