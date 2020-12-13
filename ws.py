import threading
import hashlib
import base64
import socket
import struct
import errno
import codecs
import traceback



STREAM=0x0
TEXT=0x1
BINARY=0x2
CLOSE=0x8
PING=0x9
PONG=0xa



class WSServer:
	def __init__(self,h,p,rf=lambda s,dt:None,cf=lambda s:None,df=lambda s:None):
		self.rf=rf
		self.cf=cf
		self.df=df
		cfg=socket.getaddrinfo(h,p,0,socket.SOCK_STREAM,socket.IPPROTO_TCP,socket.AI_PASSIVE)[0]
		self.ss=socket.socket(cfg[0],cfg[1],cfg[2])
		self.ss.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
		self.ss.bind(cfg[4])
		self.ss.listen(5)
		self.l=[]
		self.e=False



	def start(self):
		while (self.e==False):
			cs,a=self.ss.accept()
			cs.setblocking(0)
			threading.Thread(target=self._handle,args=(cs,a)).start()



	def stop(self):
		self.ss.close()
		self.e=True



	def send(self,dt):
		t=(TEXT if isinstance(dt,str) else BINARY)
		o=bytearray([t|0x80])
		if (isinstance(dt,str)):
			dt=dt.encode("utf-8")
		l=len(dt)
		if (l<=125):
			o.append(l)
		elif (l>=126 and l<=65535):
			o.append(126)
			o.extend(struct.pack("!H",l))
		else:
			o.append(127)
			o.extend(struct.pack("!Q",l))
		if (l>0):
			o.extend(dt)
		threading.current_thread()._cs_q.append((t,o))



	def close(self,status=1000,reason=""):
		try:
			if (not threading.current_thread()._e):
				dt=bytearray(struct.pack("!H",status))
				if (isinstance(reason,str)):
					dt.extend(reason.encode('utf-8'))
				else:
					dt.extend(reason)
				o=bytearray([CLOSE|0x80])
				if (isinstance(dt,str)):
					dt=dt.encode("utf-8")
				l=len(dt)
				if (l<=125):
					o.append(l)
				elif (l>=126 and l<=65535):
					o.append(126)
					o.extend(struct.pack("!H",l))
				else:
					o.append(127)
					o.extend(struct.pack("!Q",l))
				if (l>0):
					o.extend(dt)
				threading.current_thread()._cs_q.append((CLOSE,o))
		finally:
			threading.current_thread()._e=True



	def _handle(self,cs,a):
		threading.current_thread()._cs_q=[]
		threading.current_thread()._e=False
		sc=type("tmp",(object,),{})()
		r_hs=False
		r_hl=bytearray()
		r_f=0
		r_t=0
		r_dt=bytearray()
		r_m=0
		r_ml=None
		r_l=0
		r_ll=None
		r_i=0
		sc.frag_start=False
		sc.frag_type=BINARY
		sc.frag_buffer=None
		sc.frag_decoder=codecs.getincrementaldecoder("utf-8")(errors="strict")
		r_s=0
		while (self.e==False):
			try:
				self_=sc
				if (r_hs is False):
					dt=cs.recv(2048)
					if (not dt):
						raise Exception("Remote socket closed")
					else:
						r_hl.extend(dt)
						if (len(r_hl)>=2**16):
							raise Exception("Header exceeded allowable size")
						if (b"\r\n\r\n" in r_hl):
							try:
								for e in r_hl.split(b"\r\n\r\n")[0].split(b"\r\n")[1:]:
									if (len(e)>0 and str(e.split(b":")[0],"utf-8")=="Sec-WebSocket-Key"):
										threading.current_thread()._cs_q.append((BINARY,f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {base64.b64encode(hashlib.sha1(e[len(e.split(b':')[0])+2:]+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'.encode('ascii')).digest()).decode('ascii')}\r\n\r\n".encode("ascii")))
										r_hs=True
										self.cf(self)
										break
								if (r_hs==False):
									raise KeyError
							except Exception as e:
								dt="HTTP/1.1 426 Upgrade Required\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nContent-Type: text/plain\r\n\r\nThis service requires use of the WebSocket protocol\r\n".encode("ascii")
								i=0
								l=len(dt)
								while (i<l):
									try:
										j=cs.send(dt[i:])
										if (j==0):
											raise RuntimeError("Socket connection broken")
										i+=j
									except socket.error as e:
										if (e.errno in [errno.EAGAIN,errno.EWOULDBLOCK]):
											continue
										else:
											raise e
								cs.close()
								raise Exception(f"Handshake failed: {e}")
				else:
					try:
						dt=cs.recv(16384)
						if (not dt):
							raise Exception("Remote socket closed")
						for b in dt:
							h_dt=False
							if (r_s==0):
								r_f,rsv,r_t=b&0x80,b&0x70,b&0x0f
								r_s=1
								r_i=0
								r_l=0
								r_ll=bytearray()
								r_dt=bytearray()
								if (rsv!=0):
									raise Exception("RSV bit must be 0")
							elif (r_s==1):
								if r_t==PING and length>125:
									 raise Exception("Ping packet is too large")
								r_m=(True if b&0x80==128 else False)
								l=b&0x7F
								if (l<=125):
									r_l=l
									if (r_m is True):
										r_ml=bytearray()
										r_s=4
									else:
										if (r_l<=0):
											h_dt=True
										else:
											r_dt=bytearray()
											r_s=5
								elif (l==126):
									r_ll=bytearray()
									r_s=2
								else:
									r_ll=bytearray()
									r_s=3
							elif r_s==2:
								r_ll.append(b)
								if (len(r_ll)>2):
									raise Exception("Short length exceeded allowable size")
								if (len(r_ll)==2):
									r_l=struct.unpack_from("!H",r_ll)[0]
									if (r_m is True):
										r_ml=bytearray()
										r_s=4
									else:
										if (r_l<=0):
											h_dt=True
										else:
											r_dt=bytearray()
											r_s=5
							elif (r_s==3):
								r_ll.append(b)
								if (len(r_ll)>8):
									raise Exception("Long length exceeded allowable size")
								if (len(r_ll)==8):
									r_l=struct.unpack_from("!Q",r_ll)[0]
									if (r_m is True):
										r_ml=bytearray()
										r_s=4
									else:
										if (r_l<=0):
											h_dt=True
										else:
											r_dt=bytearray()
											r_s=5
							elif (r_s==4):
								r_ml.append(b)
								if (len(r_ml)>4):
									raise Exception("Mask exceeded allowable size")
								if (len(r_ml)==4):
									if (r_l<=0):
										h_dt=True
									else:
										r_dt=bytearray()
										r_s=5
							elif (r_s==5):
								r_dt.append((b^r_ml[r_i%4] if r_m else b))
								if (len(r_dt)>=2**25):
									raise Exception("Payload exceeded allowable size")
								if (r_i+1==r_l):
									h_dt=True
								else:
									r_i+=1
							if (h_dt):
								try:
									if (r_t==CLOSE or r_t==STREAM or r_t==TEXT or r_t==BINARY):
										pass
									elif (r_t==PONG or r_t==PING):
										if (len(r_dt)>125):
											raise Exception("Control frame length can't be >125")
									else:
										raise Exception("Unknown opcode")
									if (r_t==CLOSE):
										status=1000
										reason=""
										length=len(r_dt)
										if (length==0):
											pass
										elif (length>=2):
											status=struct.unpack_from("!H",r_dt[:2])[0]
											reason=r_dt[2:]
											if (status not in [1000,1001,1002,1003,1007,1008,1009,1010,1011,3000,3999,4000,4999]):
												status=1002
											if (len(reason)>0):
												try:
													reason=reason.decode("utf-8",errors="strict")
												except:
													status=1002
										else:
											status=1002
										self.close(status,reason)
										break
									elif (r_f==0):
										if (r_t!=STREAM):
											if (r_t==PING or r_t==PONG):
												raise Exception("Control messages can't be fragmented")
											self_.frag_type=r_t
											self_.frag_start=True
											self_.frag_decoder.reset()
											if (self_.frag_type==TEXT):
												self_.frag_buffer=[]
												utf_str=self_.frag_decoder.decode(r_dt,final=False)
												if (utf_str):
													self_.frag_buffer.append(utf_str)
											else:
												self_.frag_buffer=bytearray()
												self_.frag_buffer.extend(r_dt)
										else:
											if (self_.frag_start is False):
												raise Exception("Fragmentation protocol error")
											if (self_.frag_type==TEXT):
												utf_str=self_.frag_decoder.decode(r_dt,final=False)
												if (utf_str):
													 self_.frag_buffer.append(utf_str)
											else:
												self_.frag_buffer.extend(r_dt)
									elif (r_t==STREAM):
										if (self_.frag_start is False):
											raise Exception("Fragmentation protocol error")
										if (self_.frag_type==TEXT):
											utf_str=self_.frag_decoder.decode(r_dt,final=True)
											self_.frag_buffer.append(utf_str)
											r_dt="".join(self_.frag_buffer)
										else:
											self_.frag_buffer.extend(r_dt)
											r_dt=self_.frag_buffer
										self.cf(self,r_dt)
										self_.frag_decoder.reset()
										self_.frag_type=BINARY
										self_.frag_start=False
										self_.frag_buffer=None
									elif (r_t==PING):
										if (isinstance(r_dt,str)):
											r_dt=r_dt.encode("utf-8")
										l=len(r_dt)
										assert(l<=125)
										o=bytearray([PONG|0x80,l])
										if (l>0):
											o.extend(r_dt)
										self_.sq.append((t,o))
									elif (r_t==PONG):
										pass
									else:
										if (self_.frag_start is True):
											raise Exception("Fragmentation protocol error")
										if (r_t==TEXT):
											try:
												r_dt=r_dt.decode("utf8",errors="strict")
											except Exception as exp:
												raise Exception("Invalid utf-8 payload")
										self.rf(self,r_dt)
								except Exception as e:
									traceback.print_exception(None,e,e.__traceback__)
								r_s=0
								r_dt=bytearray()
					except BlockingIOError:
						pass
				b=False
				while (len(threading.current_thread()._cs_q)>0):
					(t,dt),threading.current_thread()._cs_q=threading.current_thread()._cs_q[0],threading.current_thread()._cs_q[1:]
					r=None
					l=len(dt)
					i=0
					while (i<l):
						try:
							j=cs.send(dt[i:])
							if (j==0):
								raise RuntimeError("Socket connection broken")
							i+=j
						except socket.error as e:
							if (e.errno in [errno.EAGAIN,errno.EWOULDBLOCK]):
								r=dt[i:]
								break
							else:
								raise e
					if (r is not None):
						threading.current_thread()._cs_q=[(t,r)]+threading.current_thread()._cs_q
						break
					elif (t==CLOSE):
						b=True
						break
				if (b==True):
					break
			except Exception as e:
				traceback.print_exception(None,e,e.__traceback__)
				break
		cs.close()
		if (r_hs):
			try:
				self.df(self)
			except Exception as e:
				traceback.print_exception(None,e,e.__traceback__)
