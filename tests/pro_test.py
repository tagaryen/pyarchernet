from archernet import ProHttpServer, ProHttpRequest, ProHttpResponse, HttpMessageListenner


class HttpMessage(HttpMessageListenner):

    def handle(self, req, res):
        q = req.get_queries()
        print(req.uri)
        print(req.method)
        print(req.content_type)
        # content = b''
        # while True:
        #     chunk = req.read_body()
        #     if len(chunk) == 0:
        #         break
        #     content += chunk
        
        print("body: {}".format(req.get_body()))
        res.set_status(200)
        res.set_content_type("application/json")
        res.set_header("xuyi", "haoshuai")
        res.send_chunk_start()
        res.send_chunk('{"徐熠":"好帅"}'.encode('utf-8'))
        res.send_chunk_end()
        # res.send_body('{"徐熠":"好帅"}'.encode('utf-8'))
        

server = ProHttpServer()

server.listen(threadnum=2, listenner=HttpMessage())
