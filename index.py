from ws import WSServer



def recv(self,dt):
	print(f"Echo: {dt}")
	self.send(f"Echo: {dt}")
def connect(self):
	print("Connect")
def disconnect(self):
	print("Close")



ws_s=WSServer("0.0.0.0",8080,recv,connect,disconnect)
try:
	print("WebSocketServer has started on port 8080!")
	ws_s.start()
except KeyboardInterrupt:
	ws_s.stop()
