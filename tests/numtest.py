
class Atest:
    def __init__(self):
        self.num = 10

def _check_base_type(v):
    t = type(v)
    if t is type :
        return True
    if t is int :
        return True
    if t is float :
        return True
    if t is complex :
        return True
    if t is bytes :
        return True
    if t is str :
        return True
    if t is tuple :
        return True
    if t is list :
        return True
    if t is dict :
        return True
    if t is set :
        return True
    return False


print(f"{type(Atest).__name__}, {_check_base_type(Atest)}")
a = Atest()
print(f"{type(a).__name__}, {_check_base_type(a)}")
a = 10
print(f"{type(a).__name__}, {_check_base_type(a)}")
a = "nia"
print(f"{type(a).__name__}, {_check_base_type(a)}")
a = b"nia"
print(f"{type(a).__name__}, {_check_base_type(a)}")
a = []
print(f"{type(a).__name__}, {_check_base_type(a)}")
a = {}
print(f"{type(a).__name__}, {_check_base_type(a)}")

        