from pyarchernet.rs_client import RSClient

cli = RSClient("10.32.123.43", 9611, "u&*1l)+yv1%*:^tg")

cli.save("nihao", "hahahahha")

print(cli.get("nihao"))