#coding=utf-8

import socket
import select
import socketserver
import logging
import json

#import time

from multiprocessing import Process
#import threading


with open('config.json', 'rb') as f:
	config = json.load(f)

#port = int(config['loaclport'])
serverdd = config['server']
port = int(config['port'])
localport = int(config['localport'])

localserver = config['localserver']

pss = config['password']
key1 = int.from_bytes(pss[1].encode(),byteorder='big')



class UDPSocks5Server(socketserver.BaseRequestHandler):



	def handle(self):
		
		
		
		
		
		
		
		#print(123)
		#print('======?>', self.request, self.server, self.client_address)
		#print(self.request)
		
		
		
		date,sockd  = self.request
		ccc = self.client_address
		

		con=b'\x02'+len(pss).to_bytes(length=1,byteorder='big')+pss.encode()+ date[4:]
		
		
		cop = xorr(con)
		
		server11 = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		server11.sendto(cop,(serverdd,port))
		
		
		data,server_addr1 = server11.recvfrom(1024*100)
		cop=xorr(data)
		
		sockd.sendto(cop,ccc)
		
		
		try:
			fds = [sockd,server_addr1]
			while True:
				r,w,e = select.select(fds,[],[],5)
				if client in r:
					cli_data = client.recv(1024 * 100)
					cli_data_de = xorr(cli_data)
					
					if len(cli_data) <= 0:
						break
					result = send_all(remote, cli_data_de)
					if result < len(cli_data):
						logging.warn("Failed pipping all data to target!!!")
						break
				if remote in r:
					remote_data = remote.recv(1024 * 100)
					#remmote_data_en=remote_data
					
					remote_data_en=xorr(remote_data)
					
					
					#print(remote_data)
					#print(remote_data_en)
					if len(remote_data) <= 0:
						break
					result = send_all(client, remote_data_en)
					if result < len(remote_data):
						logging("Failed pipping all data to client!!!")
						break
		except Exception as e:
			logging.error(e)
		finally:
			client.close()
			remote.close()



class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
	pass

#StreamRequestHandler
class Socks5Server(socketserver.StreamRequestHandler):
	def handle_tcp(self, client, remote):
		try:
			fds = [client,remote]
			while True:
				r,w,e = select.select(fds,[],[],5)
				if client in r:
					cli_data = client.recv(128)
					
					#cli_data_de = cli_data
					cli_data_de = xorr(cli_data)
					
					if len(cli_data) <= 0:
						break
					result = send_all(remote, cli_data_de)
					if result < len(cli_data):
						logging.warn("Failed pipping all data to target!!!")
						break
				if remote in r:
					remote_data = remote.recv(128)
					#remmote_data_en=remote_data
					
					remote_data_en=xorr(remote_data)
					
					
					#print(remote_data)
					#print(remote_data_en)
					if len(remote_data) <= 0:
						break
					result = send_all(client, remote_data_en)
					if result < len(remote_data):
						logging("Failed pipping all data to client!!!")
						break
		except Exception as e:
			logging.error(e)
		finally:
			client.close()
			remote.close()



	def handle(self):
		
		client = self.request
		ver,methods = client.recv(1),client.recv(1)
		methods = client.recv(ord(methods))

		client.send(b'\x05\x00')

		ver,cmd,rsv,atype = client.recv(1),client.recv(1),client.recv(1),client.recv(1)
		#print(ord(cmd))
		#if ord(cmd) is not 1:
			#client.close()
			#return

        # 判断是否支持atype，目前不支持IPv6
        # 比特流转化成整型 big表示编码为大端法，
		if(ord(cmd)==1):
			if ord(atype) == 1:
				# IPv4
				ip=client.recv(4)
				pp=client.recv(2)
				remote_addr = socket.inet_ntoa(ip)
				remote_port = int.from_bytes(pp, 'big')
				#con=b'\x01'+len(pss).to_bytes(length=1,byteorder='big')+pss.encode()+b'\x02'+ip+pp
				con=b'\x01'+len(pss).to_bytes(length=1,byteorder='big')+pss.encode()+b'\x02'+ip+pp
			elif ord(atype) == 3:
				# 域名 
				#ip=client.recv(4)
				#pp=client.recv(2)
				len1=client.recv(1)
				addr_len = int.from_bytes(len1, byteorder = 'big')
				remote_addr = client.recv(addr_len)
				print(remote_addr)
				pp=client.recv(2)
				remote_port = int.from_bytes(pp, byteorder = 'big')
				#con=b'\x01'+len(pss).to_bytes(length=1,byteorder='big')+pss.encode()+b'\x01'+len1+encode1(remote_addr,0)+pp
				con=b'\x01'+len(pss).to_bytes(length=1,byteorder='big')+pss.encode()+b'\x01'+len1+xorr(remote_addr)+pp
			else:
				#不支持则关闭连接
				client.close()
				return
			remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			logging.info('[+] %s:%dConnect to --> %s:%d' % (self.client_address[0], self.client_address[1], remote_addr, remote_port))
			#remote.connect((remote_addr, remote_port))
			remote.connect((serverdd,port))
			print(con)
			remote.send(con)
			reply = b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + (2222).to_bytes(2, byteorder = 'big')
			client.send(reply)
			if(remote.recv(2) == b'\x03\x00'):
				print("handle ok")
				self.handle_tcp(client,remote)
		if(ord(cmd)==3):
			print("UDP-Newconnection")
			
			remotetcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			remotetcp.connect((serverdd,port))
			remotetcp.send(b'\x02'+len(pss).to_bytes(length=1,byteorder='big')+pss.encode())
			bindport1=remotetcp.recv(1024*100)
			
			bindport2=int.from_bytes(bindport1,byteorder='big')
			remoteudp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			remoteudp.bind(('0.0.0.0',0))
			print(bindport1)
			
			#remoteudp.sendto(xorr(b'\x01'+len(pss).to_bytes(length=1,byteorder='big')+pss.encode()+bindport1+b'\x01\x02\x03\x04'),(serverdd,port))
			#tlo = remoteudp.recvfrom(1024*100)
			#tlo1=tlo[0]
			#print(tlo)
			#if tlo1==b'\x03\x01':
				#print('Hanle Udp OK')
			#else:
				#print('No! Cheak your password')

			sockudp = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
			sockudp.bind(('0.0.0.0',0))
			#print(b'\x05\x00\x00\x01\x00\x00\x00\x00'+sockudp.getsockname()[1].to_bytes(length=2,byteorder='big'))
			client.send(b'\x05\x00\x00\x01\x00\x00\x00\x00'+sockudp.getsockname()[1].to_bytes(length=2,byteorder='big'))
			#global tyui
	
			try:
				fds = [sockudp,remoteudp,client]
				while True:
					r,w,e = select.select(fds,[],[],5)
					for i in r:
						if i is client:
							if len(client.recv(1024))==0:
								
								print('beak connection-OUT')
								remoteudp.close()
								sockudp.close()
								client.close()
								break
						if i is remoteudp:
							#dateback1=remoteudp.recvfrom(1024*100)
							#date1=dateback1[0]
							#sockudp.sendto(,)
							dateback1=remoteudp.recvfrom(1024)
							date1=dateback1[0]
							backoo=xorr(date1)
							sockudp.sendto(backoo,user)
							
						if i is sockudp:
							dateback2=sockudp.recvfrom(1024)
							date2=dateback2[0]
							user=dateback2[1]
							data111= xorr(b'\x01'+len(pss).to_bytes(length=1,byteorder='big')+pss.encode()+bindport1+date2)
							remoteudp.sendto(data111,(serverdd,port))
							
							#dateback1=remoteudp.recvfrom(1024*100)
							#date1=dateback1[0]
							#backoo=xorr(date1)
							#sockudp.sendto(backoo,user)
							
					
			except Exception as e:
				logging.error(e)
			finally:
				client.close()
				remoteudp.close()
				sockudp.close()




			
			
			



def xorr(data):
	ddd=b''
	for i in data:
		ddd+= (i^key1).to_bytes(length=1,byteorder='big')
	return	ddd
 
def encode1(data,m):
	q=""
	for i in data:
		tt=i^9
		q=q+ chr( tt + 4 )
		#q=q+chr(i^9)
	
	j=q.encode()
	if( m == 1 ):
		return q
	else:
		return j


def decode1(data,m):
	q = ""
	for i in data:
		tt = i -4
		q=q+ chr( tt ^ 9)
		#q=q+chr(i^9)
	j=q.encode()
	if( m == 1 ):
		return q
	else:
		return j
def send_all(sock, data):

    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent
#def UDP():
	#print("UDPrunning")
	#UDPserver = socketserver.ThreadingUDPServer((localserver, localport), UDPSocks5Server)
	#UDPserver.serve_forever()
def TCP():
	server=socketserver.ThreadingTCPServer((localserver,localport),Socks5Server)
	server.serve_forever()

if __name__ == '__main__':
		try:

				#global remote1
				#remote1 = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)



				print('[+] Lintening(UDP&TCP) on port:%d' % localport)
				TCP ()
                #UDPshd = Process(target=TCP,)
                #UDPshd.start()

                #print("[+] UDPrunning in :%d" % port)
                #UDPserver = socketserver.ThreadingUDPServer((serverdd, port), UDPSocks5Server)
                #UDPserver.serve_forever()






		except Exception as e:
				logging.error(e)
