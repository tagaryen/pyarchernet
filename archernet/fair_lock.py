import threading
from collections import deque

class FairLock:
    def __init__(self):
        self._lock = threading.Lock()  
        self._wait_queue = deque()        
        self._cond = threading.Condition(self._lock)      

    def acquire(self): 
        with self._lock:
            self._wait_queue.append(threading.current_thread())
        while True:
            if self._wait_queue[0] is threading.current_thread():
                return
            with self._lock:
                self._cond.wait()

    def release(self):
        with self._lock:
            if self._wait_queue[0] is threading.current_thread():
                self._wait_queue.popleft()
                self._cond.notify_all()
