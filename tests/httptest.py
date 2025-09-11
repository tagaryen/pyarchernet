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


# c = ""
# with open('D:/da.csv', 'r', encoding='utf-8') as f:
#     c = f.read()
# multiparts = [Multipart('file', c, isFile=True, filename='data1029.csv', contentType="application/csv"), Multipart("Node-Id", 'alice')]

# --------------------------236688330272706286933682
# ----------------------------236688330272706286933682

form = FormData()
form.put("你", "好")
form.put_file("file", "D:/install.sh")
# 'content-type': Multipart.MULTIPART_HEADER_PREFIX + form.boundary
res = HttpClient.post('http://127.0.0.1:8080/paitre', {}, form)
print(res.status_code)
print(str(res.content, encoding='gbk'))


# a = bytes('{}\r\nascac'.format('nihao'), encoding='utf-8')

# print(str(a, encoding='utf-8'))




# def onresponse(res: HttpClientResponse):
#     print(res.status_code)

# file = open('./tmp.txt', 'a', encoding='utf-8-sig')
# def onchunkdata(chunk: bytes):
#     file.write(str(chunk))


# HttpClient.streamRequest("GET", "https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.16.9/xlsx.full.min.js", onresponse=onresponse, onchunk=onchunkdata)

# file.close()

