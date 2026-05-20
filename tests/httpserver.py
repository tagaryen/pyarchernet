from archernet import HttpStatusCode, HttpRequest, HttpResponse, BlockedHttpHandler, HttpServer, HttpClient, HttpClientResponse, SSLContext, Multipart, FormData

import traceback


with open('gm_cert/ca.crt', 'r', encoding='utf-8') as file:
    ca = file.read()
with open('gm_cert/server.crt', 'r', encoding='utf-8') as file:
    crt = file.read()
with open('gm_cert/server.key', 'r', encoding='utf-8') as file:
    key = file.read()
with open('gm_cert/server_en.crt', 'r', encoding='utf-8') as file:
    en_crt = file.read()
with open('gm_cert/server_en.key', 'r', encoding='utf-8') as file:
    en_key = file.read()

sslctx = SSLContext(is_client_mode = False)
sslctx.ca = ca
sslctx.crt = crt
sslctx.key = key
sslctx.en_crt = en_crt
sslctx.en_key = en_key

class MyHttp(BlockedHttpHandler):

    def on_http_message(self, req: HttpRequest, res: HttpResponse):
        res.set_header('content-type', 'text/plain')
        # res.send_content('{"nihao":"shuai"}')
        writer = res.stream_writer()
        writer.write('hello')
        writer.end()

    def on_http_error(self, e: Exception):
        traceback.print_exception(e)


server = HttpServer(2, sslctx=sslctx)
server.listen("0.0.0.0", 9666, MyHttp())