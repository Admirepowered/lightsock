#coding=utf-8

import socket
import select
import socketserver
import logging
import json
from multiprocessing import Process


with open('config.json', 'rb') as f:
	config = json.load(f)

serverdd = config['server']
port = int(config['port'])
localport = int(config['localport'])

localserver = config['localserver']

pss = config['password']
key1 = int.from_bytes(pss[1].encode(),byteorder='big')



class UDPSocks5Server(socketserver.BaseRequestHandler):



	def handle(self):
		
		
		
		
		
		
		

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

					remote_data_en=xorr(remote_data)
					
				
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
					cli_data = client.recv(1024 * 100)
					
					#cli_data_de = cli_data
					cli_data_de = xorr(cli_data)
					
					if len(cli_data) <= 0:
						break
					result = send_all(remote, cli_data_de)
					if result < len(cli_data):
						logging.warn("Failed pipping all data to target!!!")
						break
				if remote in r:
					remote_data = remote.recv(1024 * 100)

					
					remote_data_en=xorr(remote_data)
					
	
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

		if(ord(cmd)==1):
			if ord(atype) == 1:
				# IPv4
				ip=client.recv(4)
				pp=client.recv(2)
				remote_addr = socket.inet_ntoa(ip)
				remote_port = int.from_bytes(pp, 'big')

				con=b'\x09'+len(pss).to_bytes(length=1,byteorder='big')+pss.encode()+b'\x02'+ip+pp
			elif ord(atype) == 3:

				len1=client.recv(1)
				addr_len = int.from_bytes(len1, byteorder = 'big')
				remote_addr = client.recv(addr_len)
				print(remote_addr)
				pp=client.recv(2)
				remote_port = int.from_bytes(pp, byteorder = 'big')

				con=b'\x09'+len(pss).to_bytes(length=1,byteorder='big')+pss.encode()+b'\x08'+len1+xorr(remote_addr)+pp
			else:

				client.close()
				return
			remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			logging.info('[+] %s:%dConnect to --> %s:%d' % (self.client_address[0], self.client_address[1], remote_addr, remote_port))

			remote.connect((serverdd,port))
			print(con)
			remote.send(con)
			reply = b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + (2222).to_bytes(2, byteorder = 'big')
			client.send(reply)
			if(remote.recv(2) == b'\x16\x78'):
				print("handle ok")
				self.handle_tcp(client,remote)
		if(ord(cmd)==3):
			print("UDP-Newconnection")
			
			remotetcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			remotetcp.connect((serverdd,port))
			remotetcp.send(b'\x04'+len(pss).to_bytes(length=1,byteorder='big')+pss.encode())
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
			sockudp.bind(('127.0.0.1',0))
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
							dateback1=remoteudp.recvfrom(1024*100)
							date1=dateback1[0]
							backoo=xorr(date1)
							sockudp.sendto(backoo,user)
							
						if i is sockudp:
							dateback2=sockudp.recvfrom(1024*100)
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
