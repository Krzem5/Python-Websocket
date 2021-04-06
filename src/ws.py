import base64
import codecs
import errno
import hashlib
import socket
import struct
import threading
import traceback



STREAM=0x0
TEXT=0x1
BINARY=0x2
CLOSE=0x8
PING=0x9
PONG=0xa



def send(dt,thr=threading.current_thread()):
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
	threading.current_thread()._tl.acquire()
	thr._cs_q.append((t,o))
	threading.current_thread()._tl.release()



def close(s=1000,m=""):
	try:
		if (not threading.current_thread()._e):
			dt=bytearray(struct.pack("!H",s))
			if (isinstance(m,str)):
				dt.extend(m.encode("utf-8"))
			else:
				dt.extend(m)
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



def handle(cs,cf=lambda:None,rf=lambda dt:None,df=lambda:None,h_dt=None):
	cs.setblocking(0)
	threading.current_thread()._cs_q=[]
	threading.current_thread()._e=False
	threading.current_thread()._tl=threading.Lock()
	r_hs=False
	r_f=0
	r_t=0
	r_dt=bytearray()
	r_m=0
	r_ml=None
	r_l=0
	r_ll=None
	r_i=0
	r_s=0
	r_fs=False
	r_ft=BINARY
	r_fb=None
	r_fd=codecs.getincrementaldecoder("utf-8")(errors="strict")
	while (not threading.current_thread()._e):
		try:
			if (r_hs is False):
				dt=(h_dt if h_dt else cs.recv(65535))
				if (not dt):
					return
				if (b"\r\n\r\n" not in dt):
					raise RuntimeError("Header too big")
				try:
					for e in dt.split(b"\r\n\r\n")[0].split(b"\r\n")[1:]:
						if (len(e)>0 and str(e.split(b":")[0],"utf-8").lower()=="sec-websocket-key"):
							threading.current_thread()._cs_q.append((BINARY,f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {base64.b64encode(hashlib.sha1(e[len(e.split(b':')[0])+2:]+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'.encode('ascii')).digest()).decode('ascii')}\r\n\r\n".encode("ascii")))
							r_hs=True
							cf()
							break
					if (r_hs==False):
						raise KeyError
				except Exception as e:
					traceback.print_exception(None,e,e.__traceback__)
					dt="HTTP/1.1 426 Upgrade Required\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nContent-Type: text/plain\r\n\r\nThis service requires use of the WebSocket protocol\r\n".encode("ascii")
					i=0
					l=len(dt)
					while (i<l):
						try:
							j=cs.send(dt[i:])
							if (j==0):
								return
							i+=j
						except socket.error as e:
							if (e.errno in [errno.EAGAIN,errno.EWOULDBLOCK]):
								continue
							else:
								raise e
					cs.close()
					raise RuntimeError(f"Handshake failed: {e}")
			else:
				try:
					dt=cs.recv(16384)
					if (not dt):
						return
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
								raise RuntimeError("RSV bit must be 0")
						elif (r_s==1):
							if (r_t==PING and length>125):
								raise RuntimeError("Ping packet is too large")
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
								raise RuntimeError("Short length exceeded allowable size")
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
								raise RuntimeError("Long length exceeded allowable size")
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
								raise RuntimeError("Mask exceeded allowable size")
							if (len(r_ml)==4):
								if (r_l<=0):
									h_dt=True
								else:
									r_dt=bytearray()
									r_s=5
						elif (r_s==5):
							r_dt.append((b^r_ml[r_i%4] if r_m else b))
							if (len(r_dt)>=2**25):
								raise RuntimeError("Payload exceeded allowable size")
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
										raise RuntimeError("Control frame length can't be >125")
								else:
									raise RuntimeError("Unknown opcode")
								if (r_t==CLOSE):
									s=1000
									m=""
									l=len(r_dt)
									if (l==0):
										pass
									elif (l>=2):
										s=struct.unpack_from("!H",r_dt[:2])[0]
										m=r_dt[2:]
										if (s not in [1000,1001,1002,1003,1007,1008,1009,1010,1011,3000,3999,4000,4999]):
											s=1002
										if (len(m)>0):
											try:
												m=m.decode("utf-8",errors="strict")
											except UnicodeDecodeError:
												s=1002
									else:
										s=1002
									close(s,m)
									break
								elif (r_f==0):
									if (r_t!=STREAM):
										if (r_t==PING or r_t==PONG):
											raise RuntimeError("Control messages can't be fragmented")
										r_ft=r_t
										r_fs=True
										r_fd.reset()
										if (r_ft==TEXT):
											r_fb=[]
											utf_str=r_fd.decode(r_dt,final=False)
											if (utf_str):
												r_fb.append(utf_str)
										else:
											r_fb=bytearray()
											r_fb.extend(r_dt)
									else:
										if (r_fs is False):
											raise RuntimeError("Fragmentation protocol error")
										if (r_ft==TEXT):
											utf_str=r_fd.decode(r_dt,final=False)
											if (utf_str):
												 r_fb.append(utf_str)
										else:
											r_fb.extend(r_dt)
								elif (r_t==STREAM):
									if (r_fs is False):
										raise RuntimeError("Fragmentation protocol error")
									if (r_ft==TEXT):
										utf_str=r_fd.decode(r_dt,final=True)
										r_fb.append(utf_str)
										r_dt="".join(r_fb)
									else:
										r_fb.extend(r_dt)
										r_dt=r_fb
									rf(r_dt)
									r_fd.reset()
									r_ft=BINARY
									r_fs=False
									r_fb=None
								elif (r_t==PING):
									if (isinstance(r_dt,str)):
										r_dt=r_dt.encode("utf-8")
									l=len(r_dt)
									assert(l<=125)
									o=bytearray([PONG|0x80,l])
									if (l>0):
										o.extend(r_dt)
									threading.current_thread()._cs_q.append((t,o))
								elif (r_t==PONG):
									pass
								else:
									if (r_fs is True):
										raise RuntimeError("Fragmentation protocol error")
									if (r_t==TEXT):
										try:
											r_dt=r_dt.decode("utf8",errors="strict")
										except Exception as exp:
											raise RuntimeError("Invalid utf-8 payload")
									rf(r_dt)
							except Exception as e:
								traceback.print_exception(None,e,e.__traceback__)
							r_s=0
							r_dt=bytearray()
				except BlockingIOError:
					pass
			b=False
			while (len(threading.current_thread()._cs_q)>0):
				threading.current_thread()._tl.acquire()
				(t,dt),threading.current_thread()._cs_q=threading.current_thread()._cs_q[0],threading.current_thread()._cs_q[1:]
				threading.current_thread()._tl.release()
				r=None
				l=len(dt)
				i=0
				while (i<l):
					try:
						j=cs.send(dt[i:])
						if (j==0):
							return
						i+=j
					except socket.error as e:
						if (e.errno in [errno.EAGAIN,errno.EWOULDBLOCK]):
							r=dt[i:]
							break
						else:
							raise e
				if (r is not None):
					threading.current_thread()._tl.acquire()
					threading.current_thread()._cs_q=[(t,r)]+threading.current_thread()._cs_q
					threading.current_thread()._tl.release()
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
			df()
		except Exception as e:
			traceback.print_exception(None,e,e.__traceback__)
