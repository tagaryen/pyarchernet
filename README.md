# pyarchernet
network framework based on c library, support latest openssl(gmssl) 1.3 
support encrypted key and encrypted certificate  
## install:   
``` cmd
  pip install pyarchernet==1.2.0
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