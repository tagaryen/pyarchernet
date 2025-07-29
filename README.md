# pyarchernet
network framework based on c library, support latest openssl(gmssl) 1.3 
support encrypted key and encrypted certificate  
## install:   
``` cmd
  pip install pyarchernet==1.2.2
``` 
## http(s) examples:  
client:  
``` python
from pyarchernet import HttpStatusCode, HttpClient, HttpClientResponse, SSLContext

res = HttpClient.get("https://www.zhihu.com")  
print(res.status_msg)  
print(str(res.content, encoding="UTF-8"))  
  
   
res = HttpClient.post("http://127.0.0.1:8080/tomcat", {"spring": "test"})
print(str(res.content, encoding="UTF-8"))  
```

server:  
``` python
from pyarchernet import HttpStatusCode, HttpRequest, HttpResponse, BlockedHttpHandler, HttpServer, SSLContext  

import traceback  

class MyHttpHandler(BlockedHttpHandler):  

    def on_http_message(self, req: HttpRequest, res: HttpResponse):  
        print("receive " + str(req.get_content(), 'utf-8'))  
        res.set_content('{"nihao":"shuai"}')  
  
    def on_http_error(self, e: Exception):  
        traceback.print_exception(e)  

server = HttpServer(2)  
server.listen("127.0.0.1", 8080, MyHttpHandler())  
```
gmssl examples 
``` python
from pyarchernet import SSLContext 

sm2_ca = ''
sm2_crt = ''
sm2_key = ''
sm2_encrypted_crt = ''
sm2_encrypted_key = ''

with open('sm2_ca.crt', 'r') as f:
  sm2_ca = f.read()

with open('sm2_crt.crt', 'r') as f:
  sm2_crt = f.read()

with open('sm2_key.crt', 'r') as f:
  sm2_key = f.read()

with open('sm2_encrypted_crt.crt', 'r') as f:
  sm2_encrypted_crt = f.read()

with open('sm2_encrypted_key.crt', 'r') as f:
  sm2_encrypted_key = f.read()

ssl_ctx = SSLContext(is_client_mode=True)
ssl_ctx.ca = sm2_ca
ssl_ctx.crt = sm2_crt
ssl_ctx.key = sm2_key
ssl_ctx.en_crt = sm2_encrypted_crt
ssl_ctx.en_key = sm2_encrypted_key
```