import socket
import threading
import ws



def connect():
	print("Connect")
def recv(dt):
	print(f"Echo: {dt}")
	ws.send(f"Echo: {dt}")
def disconnect():
	print("Close")



try:
	cfg=socket.getaddrinfo("0.0.0.0",8080,0,socket.SOCK_STREAM,socket.IPPROTO_TCP,socket.AI_PASSIVE)[0]
	ss=socket.socket(cfg[0],cfg[1],cfg[2])
	ss.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
	ss.bind(cfg[4])
	ss.listen(5)
	print("WS Server Started on Port 8080!")
	while (True):
		cs,a=ss.accept()
		threading.Thread(target=ws.handle,args=(cs,connect,recv,disconnect)).start()
except KeyboardInterrupt:
	ss.stop()
