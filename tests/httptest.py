from pyarchernet import HttpStatusCode, HttpRequest, HttpResponse, BlockedHttpHandler, HttpServer, HttpClient, HttpClientResponse, SSLContext, Multipart, FormData

import traceback

class MyHttp(BlockedHttpHandler):

    def on_http_message(self, req: HttpRequest, res: HttpResponse):
        print("收到 " + str(req.get_content(), 'utf-8'))
        res.set_content('{"nihao":"shuai"}')

    def on_http_error(self, e: Exception):
        traceback.print_exception(e)


# server = HttpServer(2)

# server.listen("127.0.0.1", 9607, MyHttp())

# ssl_ctx = SSLContext()
# ssl_ctx.verify_peer = False

# headers = {
#     "Token": "OKCjKBw6I8ONFj2ZCrjNQJQKrsjQRc3egsVdPfMbLbUsPK7dmbh5B/OXZdyKOLPIUQwen7So1WIPooGwnRVeSYI/WUhVmkq2lWC4BXhx5UJKhnD2Uf22K//AUqYrbvGScgI08kjgnAq0fIvGnNqhL/JpSvjn2YhfB82SHIaYBJStpUmtVFkj+JHPOzJGJvaFlha/oel5p/wgww0rOxUOgq4EZOiIirh+YdsVCVOSSQUNHiCMLY2ZYH5eZEsbPyMtCCQnHc6R7vVs9lY46pcFFDBcd/VTLsWpt0WVmYxY3Iv1GDda7fdFNwEqxIP7vq1tdR8HWJR7BfGOHaByuccjBA==",
#     "Workspace": "2025061300010400001239",
#     "Content-Type": "application/json"
# }
# body = "{\"content\":{\"workspaceId\":\"2025061300010400001239\"},\"method\":\"gaia.openapi.mine.workspace.getOne\"}"
# res = HttpClient.post("https://gaiac-104.base.trustbe.cn/gaia/v1/janus/invoke/v1", headers=headers,body=bytes(body, encoding='utf-8'), ssl_ctx=ssl_ctx)

# print(res.status_msg)
# print(str(res.content, encoding="UTF-8"))

# res = HttpClient.get("https://www.zhihu.com")
c = ""
with open('D:/da.csv', 'r', encoding='utf-8') as f:
    c = f.read()
multiparts = [Multipart('file', c, isFile=True, filename='data1029.csv', contentType="application/csv"), Multipart("Node-Id", 'alice')]

bd = FormData.generateBoundary()
body = FormData.generateMultipartBody(multiparts, bd)

FormData.parseBodyToMultiparts(body, bd)

res = HttpClient.post('http://10.32.122.172:32614/api/v1alpha1/data/upload', {'User-Token': '16fa3b5d0cf1422589909b282328ea0a', 'Content-Type': Multipart.MULTIPART_HEADER_PREFIX + bd}, body)

# res = HttpClient.post('http://127.0.0.1:9607/api/v1alpha1/data/upload', {'User-Token': '16fa3b5d0cf1422589909b282328ea0a', 'Content-Type': Multipart.MULTIPART_HEADER_PREFIX + bd}, body)

# res = HttpClient.post('http://10.32.122.172:32614/api/v1alpha1/p2p/project/list', {'User-Token': '16fa3b5d0cf1422589909b282328ea0a', 'Content-Type': "application/json"}, None)

# res = HttpClient.get("https://www.zhihu.com")
print(res.status_msg)
print(str(res.content, encoding="UTF-8"))