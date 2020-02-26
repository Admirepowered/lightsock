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
pss = config['password']
key1 = int.from_bytes(pss[1].encode(),byteorder='big')



class UDPSocks5Server(socketserver.BaseRequestHandler):

		
		
		def handle(self):
				cop,sockd = self.request

				ccc = self.client_address
				
				
				date=xorr(cop)	
				
				
				
				
				if(int(date[0])==1):
						oopd = int(date[1])
						if(int( date[2:2+oopd]==pss.encode())):
								
								nowdate = date[oopd+2:]
								server11 = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
								remote_port = int.from_bytes(nowdate[0:2], 'big')
								datein = nowdate[2:]
								
								
								server11.bind(('127.0.0.1',0))
								server11.sendto(server11.getsockname()[1].to_bytes(length=2,byteorder='big')+len(ccc[0]).to_bytes(1, byteorder = 'big')+bytes(ccc[0],encoding = "utf8")+ccc[1].to_bytes(2, byteorder = 'big')+datein,(('127.0.0.1'),remote_port))
								

								server11.close()
			
				if(int(date[0])==2):
					lena=date[1]
					ipld=date[2:2+lena]

					portld=date[2+lena]*256+date[3+lena]
					date=date[4+lena:]
					date=xorr(date)
					sockd.sendto(date,(ipld,portld))
					

class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        pass

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
										#remote_data_en = remote_data
										remote_data_en = xorr(remote_data)

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
				data=client.recv(1024)
				if data[0] == 9:
						print ("TCP methon")
						if (data[2:2 + data[1]]) == pss.encode():
								print ("Password is right")
								remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
								#print(data[2 + data[1]:3 + data[1]])
								if  data[2 + data[1]:3 + data[1]] == b'\x08' :
										print("domain method")
										yumingcode=data[4 + data[1]:4 + data[1] + data[data[1]+3]]
										print(yumingcode)
										#yuming=decode1(yumingcode,1)
										yuming=xorr(yumingcode)
										print(yuming)
										tempip = socket.getaddrinfo(yuming, None)
										remoteport = ord(data[4 + data[1] + data[data[1]+3]:5 + data[1] + data[data[1]+3]])*256+ord(data[5 + data[1] + data[data[1]+3]:6 + data[1] + data[data[1]+3]])
										print(remoteport)
										remoteip=tempip[0][4][0]
										print(remoteip)
								else:
										tempip = data[3 + data[1]:7 + data[1]]
										remoteip= str(tempip[0]) +'\x2e'+ str(tempip[1]) +'\x2e'+ str(tempip[2]) + '\x2e'+ str(tempip[3])
										remoteport = ord(data[7 + data[1]:8 + data[1]])*256+ord(data[8 + data[1]:9 + data[1]])
										print(remoteip)
										print(remoteport)
								remote.connect((remoteip, remoteport))
								client.send(b'\x16\x78')
								self.handle_tcp(client,remote)
				if data[0] == 4:
						print ("UDP methon")#BAND-
						if (data[2:2 + data[1]]) == pss.encode():
								print ("Password is right")
								sockudp = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
								sockudp.bind(('0.0.0.0',0))
								
								
								remoteudp = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
								
								client.send(sockudp.getsockname()[1].to_bytes(length=2,byteorder='big'))#发送绑定端口
								print('Bind in %d'% sockudp.getsockname()[1] )
								
								
								print("UDP-Hand-OK")
								
								
								try:
									fds = [sockudp,remoteudp,client]
									print(fds)
									while True:
										r,w,e = select.select(fds,[],[],1)
										for i in r:
											if i is client:
												#print('client disconnect')
												if len(client.recv(1024))==0:
													print('Tcp-Udp End')
													remoteudp.close()
													sockudp.close()
													client.close()
													break
											if i is sockudp:
												print('client->server->web')
												jibadate,cccs = sockudp.recvfrom(1024 * 100)
												print(jibadate)
												cogpo = int.from_bytes(jibadate[0:2], 'big')
												print(cogpo)
												testdata = jibadate[2:]
												print(testdata)
												lenddd=testdata[0]
												print(lenddd)
												ipoposad=testdata[1:1+lenddd]
												print(ipoposad)
												portoposad=testdata[1+lenddd]*256+testdata[2+lenddd]
												print(portoposad)
												testdata=testdata[3+lenddd:]
												
												udpdatein = testdata
												udpdatein = udpdatein[4:]
												ipgg=str(udpdatein[0]) +'\x2e'+ str(udpdatein[1]) +'\x2e'+ str(udpdatein[2]) + '\x2e'+ str(udpdatein[3])
												print(ipgg)
												portgg=udpdatein[4]*256+udpdatein[5]
												print(portgg)
												udpdatein=udpdatein[6:]
												remoteudp.sendto(udpdatein,(ipgg,portgg))
												
											if i is remoteudp:
												print('web->server->client')
												udpdateout,lpo = remoteudp.recvfrom(1024 * 100)
												udpdateout = b'\x00\x00\x00\x01'+socket.inet_aton(lpo[0])+lpo[1].to_bytes(length=2,byteorder='big',signed=False)+udpdateout
												
												
												udpdateout = b'\x02'+len(ipoposad).to_bytes(1, byteorder = 'big')+ipoposad+portoposad.to_bytes(2, byteorder = 'big')+udpdateout
												
												coop= xorr(udpdateout)
												
												sockudp.sendto(coop,('127.0.0.1',port))
												
								except Exception as e:
									logging.error(e)
								finally:
									print('UDP Close Successfully')
									client.close()
									remoteudp.close()
									sockudp.close()
								
def send_all(sock, data):

    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent
def xorr(data):
        ddd=b''
        for i in data:
                ddd+= (i^key1).to_bytes(length=1,byteorder='big')
        return  ddd

def TCP():
        server=socketserver.ThreadingTCPServer((serverdd,port),Socks5Server)
        server.serve_forever()

if __name__ == '__main__':
		try:


				UDPshd = Process(target=TCP,)
				UDPshd.start()
				print("UDPrunning in :%d" % port)
				UDPserver = socketserver.ThreadingUDPServer((serverdd, port), UDPSocks5Server)
				UDPserver.serve_forever()
				

				print('[+] Lintening(UDP&TCP) on port:%d' % port)
				






		except Exception as e:
				logging.error(e)