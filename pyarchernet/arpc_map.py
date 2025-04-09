from typing import Callable


class ARCPCallbackMap:
    C = 127

    m: int
    arr: list

    def __init__(self):
        self.m = self.C
        self.arr = []
        for _ in range(self.C):
            self.arr.append(None)
	
    def add(self, s: bytes, cb: Callable):
        p = 0
        for i in range(len(s)):
            l = s[i]
            if(l < 0):
                l += 256
            p |= (l << ((len(s) - i) << 3))
        if(p < 0):
            p = -p 
        r = int(p % self.m)
        if self.arr[r] is None:
            self.arr[r] = {"cb": cb, "seq": s, "next": None, "last": None}
        else:
            n = {"cb": cb, "seq": s, "next": None, "last": None}
            cur = self.arr[r]
            while cur["next"] is not None:
                cur = cur["next"]
            cur["next"] = n
            n["last"] = cur

    def get(self, s: bytes):
        p = 0
        for i in range(len(s)):
            l = s[i]
            if(l < 0):
                l += 256
            p |= (l << ((len(s) - i) << 3))
        if(p < 0):
            p = -p 
        r = int(p % self.m)
        cur = self.arr[r]
        depth = 0
        while cur is not None:
            d = cur["seq"]
            if len(d) == len(s):
                ok = True
                for i in range(len(d)):
                    if d[i] != s[i]:
                        ok = False
                        break
                if ok:
                    if depth == 0:
                        self.arr[r] = cur["next"]
                        if self.arr[r] is not None:
                            self.arr[r]["last"] = None
                    else:
                        if cur["last"] is not None:
                            cur["last"]["next"] = cur["next"]
                        if cur["next"] is not None:
                            cur["next"]["last"] = cur["last"]
                    return cur["cb"]
            depth += 1
        return None