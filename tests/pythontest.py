from archernet import *
import threading
import time

class MyHandler(Handler):

    def on_connect(self, channel):
        if channel.client_mode:
            channel.send("client hello")
        else:
            print(f"channel {channel.host}:{channel.port} connected")
    
    def on_read(self, channel, data):
        print(f"channel {channel.host}:{channel.port} read {data}")




def start_server():
    server = ServerChannel()

    server.handler = MyHandler()

    server.listen()

t = threading.Thread(target=start_server)
t.start()

time.sleep(1)


channel = Channel()

channel.handler =  MyHandler()

channel.connect()

time.sleep(1)