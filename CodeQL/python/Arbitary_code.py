import pickle
import socket

class RemoteExecution:
    def __reduce__(self):
        import os
        return os.system, ('echo Hello World',)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('localhost', 8080))
s.listen(1)

while True:
    conn, addr = s.accept()
    print('Connected by', addr)
    data = conn.recv(1024)
    if not data:
        break
    try:
        obj = pickle.loads(data)
        print(obj)
    except:
        pass
    conn.close()