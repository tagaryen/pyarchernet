from .channel import Channel
from .handlers import Handler, ChannelContext
from .handlerlist import HandlerList
from .sslcontext import SSLContext
from .unordered_map import UnorderedMap
from .server_channel import ServerChannel

from urllib.parse import unquote
import threading, traceback
from abc import abstractmethod
from datetime import datetime

class HttpError(RuntimeError):
    def __init__(self, *args):
        super().__init__(*args)

class HttpStatusCode():
    CONTINUE = 100
    SWITCHING_PROTOCOLS = 101
    PROCESSING = 102
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NON_AUTHORITATIVE_INFORMATION = 203
    NO_CONTENT = 204
    RESET_CONTENT = 205
    PARTIAL_CONTENT = 206
    MULTI_STATUS = 207
    MULTIPLE_CHOICES = 300
    MOVED_PERMANENTLY = 301
    FOUND = 302
    SEE_OTHER = 303
    NOT_MODIFIED = 304
    USE_PROXY = 305
    TEMPORARY_REDIRECT = 307
    PERMANENT_REDIRECT = 308
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    PAYMENT_REQUIRED = 402
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    NOT_ACCEPTABLE = 406
    PROXY_AUTHENTICATION_REQUIRED = 407
    REQUEST_TIMEOUT = 408
    CONFLICT = 409
    GONE = 410
    LENGTH_REQUIRED = 411
    PRECONDITION_FAILED = 412
    REQUEST_ENTITY_TOO_LARGE = 413
    REQUEST_URI_TOO_LONG = 414
    UNSUPPORTED_MEDIA_TYPE = 415
    REQUESTED_RANGE_NOT_SATISFIABLE = 416
    EXPECTATION_FAILED = 417
    MISDIRECTED_REQUEST = 421
    UNPROCESSABLE_ENTITY = 422
    LOCKED = 423
    FAILED_DEPENDENCY = 424
    UNORDERED_COLLECTION = 425
    UPGRADE_REQUIRED = 426
    PRECONDITION_REQUIRED = 428
    TOO_MANY_REQUESTS = 429
    REQUEST_HEADER_FIELDS_TOO_LARGE = 431
    INTERNAL_SERVER_ERROR = 500
    NOT_IMPLEMENTED = 501
    BAD_GATEWAY = 502
    SERVICE_UNAVAILABLE = 503
    GATEWAY_TIMEOUT = 504
    HTTP_VERSION_NOT_SUPPORTED = 505
    VARIANT_ALSO_NEGOTIATES = 506
    INSUFFICIENT_STORAGE = 507
    NOT_EXTENDED = 510
    NETWORK_AUTHENTICATION_REQUIRED = 511

def __status_to_statusmessage(code: int) -> str:
    code_map = {
        100: "Continue", 
        101: "Switching Protocols", 
        102: "Processing", 
        200: "OK", 
        201: "Created", 
        202: "Accepted", 
        203: "Non-Authoritative Information", 
        204: "No Content", 
        205: "Reset Content", 
        206: "Partial Content", 
        207: "Multi-Status", 
        300: "Multiple Choices", 
        301: "Moved Permanently", 
        302: "Found", 
        303: "See Other", 
        304: "Not Modified", 
        305: "Use Proxy", 
        307: "Temporary Redirect", 
        308: "Permanent Redirect", 
        400: "Bad Request", 
        401: "Unauthorized", 
        402: "Payment Required", 
        403: "Forbidden", 
        404: "Not Found", 
        405: "Method Not Allowed", 
        406: "Not Acceptable", 
        407: "Proxy Authentication Required", 
        408: "Request Timeout", 
        409: "Conflict", 
        410: "Gone", 
        411: "Length Required", 
        412: "Precondition Failed", 
        413: "Request Entity Too Large", 
        414: "Request-URI Too Long", 
        415: "Unsupported Media Type", 
        416: "Requested Range Not Satisfiable", 
        417: "Expectation Failed", 
        421: "Misdirected Request", 
        422: "Unprocessable Entity", 
        423: "Locked", 
        424: "Failed Dependency", 
        425: "Unordered Collection", 
        426: "Upgrade Required", 
        428: "Precondition Required", 
        429: "Too Many Requests", 
        431: "Request Header Fields Too Large", 
        500: "Internal Server Error", 
        501: "Not Implemented", 
        502: "Bad Gateway", 
        503: "Service Unavailable", 
        504: "Gateway Timeout", 
        505: "HTTP Version Not Supported", 
        506: "Variant Also Negotiates", 
        507: "Insufficient Storage", 
        510: "Not Extended", 
        511: "Network Authentication Required", 
    }
    if code not in code_map:
        return "Bad Request"
    return code_map[code]

class HttpRequest():

    __host: str
    __port: int
    __content: bytes
    __cache: bytes
    __uri: str

    def __init__(self, ctx: ChannelContext):
        self.__host = ctx.channel.host
        self.__port = ctx.channel.port
        self.__method = "GET"
        self.__version = "HTTP/1.1"
        self.__uri = ""
        self.__ok = True
        self.__headparsed = False
        self.__finished = False
        self.__querys = {}
        self.__headers = {}
        self.__content_length = -1
        self.__chunked = False
        self.__content = b''
        self.__cache = b''

    def host(self) -> str:
        return self.__host

    def port(self):
        return self.__port
    
    
    @property
    def ok(self) -> bool:
        return self.__ok
    
    @property
    def headparsed(self) -> bool:
        return self.__headparsed
    
    @property
    def finished(self) -> bool:
        return self.__finished
    
    @property
    def chunked(self) -> bool:
        return self.__chunked

    @property
    def uri(self) -> str:
        return self.__uri
    
    @property
    def method(self) -> str:
        return self.__method
    
    @property
    def version(self) -> str:
        return self.__version

    def get_query(self, key: str) -> str:
        return self.__querys[key]

    def get_all_querys(self) -> dict[str]:
        return self.__querys
    
    def get_header(self, key:str) -> str:
        return self.__headers[key]

    def get_all_headers(self) -> dict[str]:
        return self.__headers

    def get_content_length(self) -> int:
        return 0 if self.__content_length <= 0 else self.__content_length
    
    def get_content(self) -> bytes:
        return self.__content
    
    
    def __parse_url(self, url: str) -> bool:
        us = url.split('?')
        self.__uri = us[0]
        c = len(us)
        if c == 1:
            return True
        if c != 2:
            return False
        querys = us[1]
        query_arr =  querys.split('&')
        for q in query_arr:
            kv = q.split('=')
            if len(kv) == 1:
                self.__querys[unquote(kv[0])] = ""
            elif len(kv) == 2:
                self.__querys[unquote(kv[0])] = unquote(kv[1])
            else:
                self.__querys[unquote(kv[0])] = unquote("=".join(kv[1:]))
        return True


    def __parse_head(self, text: bytes):
        lines = text.splitlines()
        count = len(lines)
        if count < 3:
            self.__ok = False
            self.__err = "Bad Request. Head lines less than 3"
            return 
        title = str(lines[0], 'utf-8').strip()
        titles = title.split(' ')
        if len(titles) != 3:
            self.__ok = False
            self.__err = "Bad Request. Bad Header " + title
            return 
        self.__method = titles[0].strip()
        if not self.__parse_url(titles[1].strip()):
            self.__ok = False
            self.__err = "Bad Request. Bad Url " + titles[1].strip()
            return 
        self.__version = titles[2].strip()
        idx = 0
        for i in range(1, count):
            line = str(lines[i], 'utf-8').strip()
            if line == '':
                idx = i + 1
                break
            t = line.find(':')
            if t <= 0 or t >= len(line) - 1:
                self.__ok = False
                self.__err = "Bad Request. Bad Header " + line
                return 
            k = line[0:t].strip()
            v = line[t+1:].strip()
            self.__headers[k.lower()] = v
        l = idx
        if l > 3:
            self.__headparsed = True
        if l >= count - 1:
            self.__cache = b'\n'.join(lines[l:])
            return 
        
        remain = b'\n'.join(lines[l:])
        if "content-length" in self.__headers:
            try:
                self.__content_length = int(self.__headers["content-length"])
            except ValueError as r:
                self.__ok = False
                self.__err = "Bad Request. Bad Content-Length: " + self.__headers["content-length"]
                return 
            if len(remain) >= self.__content_length:
                self.__content = remain[0:self.__content_length]
                self.__finished = True
            else:
                self.__content = remain

        elif "transfer-encoding" in self.__headers and 'chunked' == self.__headers["transfer-encoding"]:
            self.__chunked = True
            while True:
                c = len(remain)
                lf = remain.find(b'\n')
                if lf <= 0:
                    self.__cache = remain
                    return 
                chunked_len = int(remain[0:lf].strip(), 16)
                if chunked_len == 0:
                    self.__finished = True
                    return
                if c < chunked_len+lf+1:
                    self.__cache = remain
                    return 
                else:
                    self.__content += remain[lf+1: lf+1+chunked_len]
                    if c == chunked_len+lf+1:
                        return 
                    remain = remain[lf+1+chunked_len:]
                    if remain[0] == 13:
                        remain = remain[1:]
                    if remain[0] == 10:
                        remain = remain[1:]
        else:
            self.__ok = False
            self.__err = "Bad Request. Unknown content"
            return 
    
    def __parse_content(self, text:bytes):
        if self.__chunked:
            text = self.__cache + text
            self.__cache = b''
            while True:
                lf = text.find('\n')
                if lf <= 0:
                    self.__cache = text
                    return 
                chunked_len = int(text[0:lf].strip(), 16)
                if chunked_len == 0:
                    self.__finished = True
                    return
                if len(text[lf+1:]) < chunked_len:
                    self.__cache = text
                    return 
                else:
                    self.__content += text[lf+1: lf+1+chunked_len]
                    text = text[lf+1+chunked_len:]
                    if text[0] == '\r':
                        text = text[1:]
                    if text[0] == '\n':
                        text = text[1:]
        else:
            exists_len = len(self.__content)
            need_len = self.__content_length - exists_len
            if len(text) >= need_len:
                self.__content += text[:need_len]
                self.__finished = True
                return
            else:
                self.__content += text


class HttpResponse():
    def __init__(self):
        self.__version = "HTTP/1.1"
        self.__status_code = 200
        self.__status = "200 OK"
        self.__raw_headers = "Server: Archer HTTP Server Python\r\nConnection: close\r\n"
        self.__headers = {}
        self.__encoding = 'utf-8'
        self.__content = None
        self.__content_length = 0

    def set_status(self, code: int):
        self.__status_code = code
        self.__status = code + " " + __status_to_statusmessage(code)

    def set_header(self, key:str, val:str):
        self.__headers[key.lower()] = val

    def get_header(self, key:str):
        return self.__headers[key.lower()]

    def set_content_encoding(self, encodig:str):
        self.__encoding = encodig
    
    def set_content(self, content: str|bytes):
        if isinstance(content, str):
            self.__content = bytes(content, encoding=self.__encoding)
        elif isinstance(content, bytes):
            self.__content = content
        self.__content_length = len(self.__content)
        self.__headers["content-length"] = self.__content_length

    def __to_channel_bytes(self) -> bytes:
        res = self.__version + " " + self.__status + "\r\n" + self.__raw_headers
        if "date" not in self.__headers:
            res += "Date: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\r\n"
        if self.__content is not None and "content-type" not in self.__headers:
            self.__headers['content-type'] = "text/html"
        for k, v in self.__headers.items():
            res += "{}: {}\r\n".format(k, v)
        res += "\r\n"
        res = bytes(res, self.__encoding)
        
        if self.__content is not None:
            res += self.__content
        return res

    
class BlockedHttpHandler(Handler):

    def __init__(self):
        self.__http_map = UnorderedMap()
        self.__map_lock = threading.Lock()
        super().__init__()

    def on_read(self, ctx: ChannelContext, data: bytes):
        req = self.__get_http_request(ctx)
        res = self.__get_http_response(ctx)

        if not req.headparsed:
            req._HttpRequest__parse_head(data)
        else:
            req._HttpRequest__parse_content(data)
        if not req.ok:
            res.set_status(HttpStatusCode.BAD_REQUEST)
            self.on_http_error(Exception(req.__err))
        else:
            res._HttpResponse__version = req._HttpRequest__version
            if req.finished:
                self.on_http_message(req, res)
        
        ctx.to_prev_handler_on_write(res._HttpResponse__to_channel_bytes())

        self.__reset_http_request(ctx)
        
        
    def on_error(self, ctx: ChannelContext, e: Exception):
        self.on_http_error(e)
    
    
    def on_close(self, ctx: ChannelContext):
        self.__reset_http_request(ctx)

    @abstractmethod
    def on_http_message(self, req: HttpRequest, res: HttpResponse):
        pass
    
    
    @abstractmethod
    def on_http_error(self, e: Exception):
        pass

    def __reset_http_request(self, ctx: ChannelContext):
        with self.__map_lock:
            self.__http_map.delete(ctx.channel.get_id())

    def __get_http_request(self, ctx: ChannelContext) -> HttpRequest:
        with self.__map_lock:
            pack = self.__http_map.get(ctx.channel.get_id())
            if pack is None:
                req = HttpRequest(ctx)
                res = HttpResponse()
                pack = {"req":req, "res":res}
                self.__http_map.put(ctx.channel.get_id(), pack)
            return pack["req"]
    
    def __get_http_response(self, ctx: ChannelContext) -> HttpResponse:
        with self.__map_lock:
            pack = self.__http_map.get(ctx.channel.get_id())
            if pack is None:
                req = HttpRequest(ctx)
                res = HttpResponse()
                pack = {"req":req, "res":res}
                self.__http_map.put(ctx.channel.get_id(), pack)
            return pack["res"]

class HttpServer():
    def __init__(self, threads: int = 0, sslctx: SSLContext = None):
        if threads > 128:
            threads = 128
        if threads < 0:
            threads = 0
        self._threads = threads
        self._sslctx = sslctx
        pass

    def listen_async(self, host: str, port: int, handler: BlockedHttpHandler):
        self.__do_listen(host, port, handler=handler, is_async=True)

    def listen(self, host: str, port: int, handler: BlockedHttpHandler):
        self.__do_listen(host, port, handler=handler, is_async=False)
    
    def __do_listen(self, host: str, port: int, handler: BlockedHttpHandler, is_async: bool):
        if handler is None:
            raise Exception("param handler is None")
        handlerList = HandlerList()
        handlerList.add_handler(handler)
        self.__server = ServerChannel(host, port, self._threads, self._sslctx, handlerlist=handlerList)
        if is_async:
            self.__server.listen_async()
        else:
            self.__server.listen()

    def close(self):
        if self.__server is not None:
            self.__server.close()


class HttpClientResponse():

    def __init__(self):
        self.__version = "HTTP/1.1"
        self.__status_code = 200
        self.__status_msg = "200 ok"
        self.__ok = True
        self.__headparsed = False
        self.__finished = False
        self.__headers = {}
        self.__content_length = -1
        self.__chunked = False
        self.__content = b''
        self.__cache = b''
        self.__ex = None

    @property
    def ok(self) -> bool:
        return self.__ok
    
    @property
    def headparsed(self) -> bool:
        return self.__headparsed
    
    @property
    def finished(self) -> bool:
        return self.__finished
    
    @property
    def chunked(self) -> bool:
        return self.__chunked
    
    @property
    def version(self) -> str:
        return self.__version
    
    @property
    def status_code(self) -> str:
        return self.__status_code
    
    @property
    def status_msg(self) -> str:
        return self.__status_msg
    
    @property
    def content(self) -> bytes:
        return self.__content
    
    def get_header(self, key: str) -> str:
        return self.__headers[key]
    
    def get_all_headers(self) -> map:
        return self.__headers

    def __parse_head(self, text: bytes):
        lines = text.splitlines()
        count = len(lines)
        if count < 3:
            self.__ok = False
            self.__err = "Invalid Http Response. "
            return 
        title = str(lines[0], 'utf-8').strip()
        p = title.find(' ')
        if p <= 0:
            self.__ok = False
            self.__err = "Invalid Http Response. Bad Head " + title
            return 
        self.__version = title[0:p].strip()
        title = title[p+1:].strip()
        p = title.find(' ')
        if p <= 0:
            self.__ok = False
            self.__err = "Invalid Http Response. Bad Head " + title
            return 
        try:
            self.__status_code = int(title[0:p].strip())
        except ValueError:
            self.__ok = False
            self.__err = "Invalid Http Response. Bad Status Code {}".format(title[0:p].strip())
            return 
        self.__status_msg = "{} {}".format(self.__status_code, title[p+1:].strip())
        idx = 0
        for i in range(1, count):
            line = str(lines[i], 'utf-8').strip()
            if line == '':
                idx = i + 1
                break
            t = line.find(':')
            if t <= 0 or t >= len(line) - 1:
                self.__ok = False
                self.__err = "Bad Request. Bad Header " + line
                return 
            k = line[0:t].strip()
            v = line[t+1:].strip()
            self.__headers[k.lower()] = v
        l = idx
        if l > 3:
            self.__headparsed = True
        if l >= count - 1:
            self.__cache = b'\n'.join(lines[l:])
            return 
        
        remain = b'\n'.join(lines[l:])
        if "content-length" in self.__headers:
            try:
                self.__content_length = int(self.__headers["content-length"])
            except ValueError as r:
                self.__ok = False
                self.__err = "Bad Request. Bad Content-Length: " + self.__headers["content-length"]
                return 
            if len(remain) >= self.__content_length:
                self.__content = remain[0:self.__content_length]
                self.__finished = True
            else:
                self.__content = remain

        elif "transfer-encoding" in self.__headers and 'chunked' == self.__headers["transfer-encoding"]:
            self.__chunked = True
            while True:
                c = len(remain)
                lf = remain.find(b'\n')
                if lf <= 0:
                    self.__cache = remain
                    return 
                chunked_len = int(remain[0:lf].strip(), 16)
                if chunked_len == 0:
                    self.__finished = True
                    return
                if c < chunked_len + lf + 1:
                    self.__cache = remain
                    return 
                else:
                    self.__content += remain[lf+1: lf+1+chunked_len]
                    if lf+1+chunked_len == c:
                        return 
                    remain = remain[lf+1+chunked_len:]
                    if remain[0] == 13:
                        remain = remain[1:]
                    if remain[0] == 10:
                        remain = remain[1:]
        else:
            self.__ok = False
            self.__err = "Bad Request. Unknown content"
            return 
    
    def __parse_content(self, text:bytes):
        if self.__chunked:
            text = self.__cache + text
            self.__cache = b''
            while True:
                lf = text.find(b'\n')
                if lf <= 0:
                    self.__cache = text
                    return 
                chunked_len = int(text[0:lf].strip(), 16)
                if chunked_len == 0:
                    self.__finished = True
                    return
                if len(text[lf+1:]) < chunked_len:
                    self.__cache = text
                    return 
                else:
                    self.__content += text[lf+1: lf+1+chunked_len]
                    text = text[lf+1+chunked_len:]
                    if text[0] == '\r':
                        text = text[1:]
                    if text[0] == '\n':
                        text = text[1:]
        else:
            exists_len = len(self.__content)
            need_len = self.__content_length - exists_len
            if len(text) >= need_len:
                self.__content += text[:need_len]
                self.__finished = True
                return
            else:
                self.__content += text



class _HttpClientHandler(Handler):

    def __init__(self, req_text: bytes, res: HttpClientResponse):
        self.req_text = req_text
        self.res = res
        super().__init__()
    
    def on_connect(self, ctx: ChannelContext):
        ctx.to_prev_handler_on_write(self.req_text)

    def on_read(self, ctx: ChannelContext, data: bytes):
        if not self.res.headparsed:
            self.res._HttpClientResponse__parse_head(data)
        else:
            self.res._HttpClientResponse__parse_content(data)
        
        if not self.res.ok:
            self.on_finish(ctx)
        
        if self.res.finished:
            self.on_finish(ctx)
        
        
    def on_error(self, ctx: ChannelContext, e: Exception):
        self.res._HttpClientResponse__ex = e
    
    def on_finish(self, ctx: ChannelContext):
        ctx.close()

class HttpClient():
    
    @staticmethod
    def get(url: str, headers: dict[str:str] = {}, ssl_ctx: SSLContext = None) -> HttpClientResponse:
        return HttpClient.request("GET", url, headers=headers, ssl_ctx=ssl_ctx)
        
    @staticmethod
    def post(url: str, headers: dict[str:str] = {}, body: bytes = None, ssl_ctx: SSLContext = None) -> HttpClientResponse:
        return HttpClient.request("POST", url, headers=headers, body=body, ssl_ctx=ssl_ctx)
    
    @staticmethod
    def put(url: str, headers: dict[str:str] = {}, body: bytes = None, ssl_ctx: SSLContext = None) -> HttpClientResponse:
        return HttpClient.request("PUT", url, headers=headers, body=body, ssl_ctx=ssl_ctx)
    
    @staticmethod
    def delete(url: str, headers: dict[str:str] = {}, body: bytes = None, ssl_ctx: SSLContext = None) -> HttpClientResponse:
        return HttpClient.request("DELETE", url, headers=headers, body=body, ssl_ctx=ssl_ctx)
    
    @staticmethod
    def option(url: str, headers: dict[str:str] = {}, body: bytes = None, ssl_ctx: SSLContext = None) -> HttpClientResponse:
        return HttpClient.request("OPTION", url, headers=headers, body=body, ssl_ctx=ssl_ctx)
    
    @staticmethod
    def request(method: str, url: str, headers: dict = {}, body: bytes = None, ssl_ctx: SSLContext = None) -> HttpClientResponse:
        methods = ["GET", "POST", "PUT", "DELETE", "OPTION"]
        if method not in methods:
            raise ValueError("Invalid method " + url)
        if url.startswith("http://"):
            t = url[7:]
            ssl = False
        elif url.startswith("https://"):
            t = url[8:]
            ssl = True
        else:
            raise ValueError("Invalid url " + url)
        c = len(t)
        endpoint_idx = t.find("/")
        if endpoint_idx <= 0:
            endpoint_idx = c
        endpoint = t[0:endpoint_idx]
        host_port = endpoint.split(':')
        if len(host_port) == 1:
            host = host_port[0]
            port = 443 if ssl else 80
        elif len(host_port) == 2:
            host = host_port[0]
            port = int(host_port[1])
        else:
            raise ValueError("Invalid url " + url)
        if endpoint_idx == c:
            uri = '/'
        else:
            uri = t[endpoint_idx:]
        content = "{} {} HTTP/1.1\r\n".format(method, uri)
        newheaders = {}

        if headers is not None:
            if not isinstance(headers, dict):
                raise ValueError("Invalid headers type {}".format(type(headers)))
            for k, v in headers.items():
                newheaders["{}".format(k).strip().lower()] = "{}".format(v).strip()
        newheaders["host"] = "{}:{}".format(host, port)
        if "user-agent" not in newheaders:
            newheaders["User-Agent"] = "Archer Net. Python"
        if "connection" not in newheaders:
            newheaders["Connection"] = "close"
        if body is not None:
            if "content-type" not in newheaders:
                newheaders["content-type"] = "text/txt"
            newheaders["content-length"] = "{}".format(len(body))
        else:
            del newheaders["content-type"]
            del newheaders["content-length"]

        for k,v in newheaders.items():
            content += "{}: {}\r\n".format(k, v)
        content += "\r\n"
        encoding =  newheaders["content-encoding"] if "content-encoding" in newheaders else 'utf-8'
        content = bytes(content, encoding)
        if body is not None:
            content += body
        handlerlist = HandlerList()
        res = HttpClientResponse()
        handler = _HttpClientHandler(content, res)
        handlerlist.add_handler(handler)
        if ssl:
            if ssl_ctx is None:
                ctx = SSLContext()
            else:
                ctx = ssl_ctx
        else:
            ctx = None
        ch = Channel(host, port, sslctx = ctx, handlerlist=handlerlist)
        ch.connect()

        res = handler.res
        if res._HttpClientResponse__ex is not None:
            raise res._HttpClientResponse__ex
        if not res.ok:
            raise HttpError(res._HttpClientResponse__err)
        
        return res