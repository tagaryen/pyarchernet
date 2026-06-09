from archernet.rs_client import RSClient

import threading

cli = RSClient("10.32.123.43", 9611, "u&*1l)+yv1%*:^tg")

def test():
    cli.save("nihao", "hahahahha")

    print(cli.get("nihao"))

t1 = threading.Thread(target=test)
t2 = threading.Thread(target=test)
t3 = threading.Thread(target=test)
t4 = threading.Thread(target=test)

t1.start()
t2.start()
t3.start()
t4.start()

