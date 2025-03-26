class Node:
    num: int
    data: None
    next: None

    def __init__(self, num, data):
        self.num = num
        self.data = data
        self.next = None



class UnorderedMap:
    __arr: list
    __size: int

    def __init__(self, size = 17):
        self.__size = size
        self.__arr = [None for _ in range(size)]

    def put(self, k: int, v):
        off = k % self.__size
        if self.__arr[off] is None:
            self.__arr[off] = Node(k, v)
        else:
            cur = self.__arr[off]
            while cur.next is not None:
                cur = cur.next
            cur.next = Node(k, v)
    
    def get(self, k: int):
        off = k % self.__size
        if self.__arr[off] is None:
            return None
        else :
            cur = self.__arr[off]
            if cur.num == k:
                return cur.data
            while cur.next is not None:
                if cur.next.num == k:
                    return cur.next.data
                cur = cur.next
            return None
    
    def delete(self, k: int):
        off = k % self.__size
        if self.__arr[off] is not None:
            cur = self.__arr[off]
            if cur.num == k:
                self.__arr[off] = cur.next
                return
            while cur.next is not None:
                if cur.next.num == k:
                    cur.next = cur.next.next
                    return
                cur = cur.next