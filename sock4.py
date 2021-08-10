import socket
import select
import socketserver
import logging
import json
#import http

from multiprocessing import Process


with open('config.json', 'rb') as f:

        config = json.load(f)

#port = int(config['loaclport'])
serverdd = config['server']
port = int(config['port'])
pss = config['password']
key1 = int.from_bytes(pss[1].encode(),byteorder='big')



class UDPSocks5Server(socketserver.BaseRequestHandler):

		
		
		def handle(self):
				cop,sockd = self.request
				#print(cop)
				#UDPsocked = sockd

				ccc = self.client_address
				
				
				date=xorr(cop)	
				
				
				
				
				if(int(date[0])==1):
						#转发入
						oopd = int(date[1])
						if(int(date[2:2+oopd]==pss.encode())):
								
								nowdate = date[oopd+2:]
								server11 = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
								remote_port = int.from_bytes(nowdate[0:2], 'big')
								datein = nowdate[2:]
								
								#if datein == b'\x01\x02\x03\x04':
									#print('ip information')
									#sockd.sendto(b'\x03\x01',ccc)
									#server11.sendto(len(ccc[0]).to_bytes(1, byteorder = 'big')+bytes(ccc[0],encoding = "utf8")+ccc[1].to_bytes(2, byteorder = 'big'),(('0.0.0.0'),remote_port))
									
								#else:
									#print('send-OK')
									#print(datein)
									#print(remote_port)
								#server11.sendto(,(('0.0.0.0'),remote_port))
								
								
								server11.bind(('127.0.0.1',0))
								server11.sendto(server11.getsockname()[1].to_bytes(length=2,byteorder='big')+len(ccc[0]).to_bytes(1, byteorder = 'big')+bytes(ccc[0],encoding = "utf8")+ccc[1].to_bytes(2, byteorder = 'big')+datein,(('127.0.0.1'),remote_port))
								
								
								#datey,user = server11.recvfrom(1024*100)
								#sockd.sendto(datey,ccc)
								
								server11.close()
								#sockd.close()				
				if(int(date[0])==2):
					#print('OK')
					#print(date)
					#转发出
					#print(date)
					lena=date[1]
					#print(lena)
					ipld=date[2:2+lena]
					#print(ipld)
					portld=date[2+lena]*256+date[3+lena]
					#print(portld)
					date=date[4+lena:]
					#print(date)
					date=xorr(date)
					sockd.sendto(date,(ipld,portld))
					
					#remote_ip=socket.inet_ntoa(date[1:5])
								#remote_ip=socket.inet_ntoa(nowdate[0:4])
								#remote_port=int.from_bytes(nowdate[4:6], 'big')
								#print(remote_ip)
								#print(remote_port)
								#sendpp=nowdate[6:]
								#print(sendpp)
								#server11 = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
								#server11.sendto(sendpp,(remote_ip,remote_port))

								#reply = b'\x00\x00\x00\x01'
								#data_s,server_addr1 = server11.recvfrom(1024*100)
								#reply+=nowdate[0:6]+data_s

								#cop = xorr(reply)
								#sockd.sendto(cop,ccc)
								#server11.close()
class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        pass

class Socks5Server(socketserver.StreamRequestHandler):


		def handle_tcp(self, client, remote):
				try:
						fds = [client,remote]
						while True:
								r,w,e = select.select(fds,[],[],5)
								if client in r:
										cli_data = client.recv(1024)
										#cli_data_de = cli_data
										cli_data_de = xorr(cli_data)


										if len(cli_data) <= 0:
												break
										result = send_all(remote, cli_data_de)
										if result < len(cli_data):
												logging.warn("Failed pipping all data to target!!!")
												break
								if remote in r:
										remote_data = remote.recv(1024)
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
				#client.send(b'\x05\x00')
				#client.recv(1000)
				#client.send(b"\x05\x00\x00\x03" + socket.inet_aton("0.0.0.0") + (port).to_bytes(2, byteorder = 'big'))
				
				
				
				if data[0] == 1:
						print ("TCP methon")
						if (data[2:2 + data[1]]) == pss.encode():
								print ("Password is right")
								remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
								#print(data[2 + data[1]:3 + data[1]])
								if  data[2 + data[1]:3 + data[1]] == b'\x01' :
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
										#print (remoteip[0][4][0])
										#sock.send('\x03\x00')
								remote.connect((remoteip, remoteport))
								client.send(b'\x03\x00')
								self.handle_tcp(client,remote)
				if data[0] == 2:
						print ("UDP methon")#BAND-
						if (data[2:2 + data[1]]) == pss.encode():
								print ("Password is right")
								#ooo=data[2+data[1]:]
								sockudp = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
								sockudp.bind(('0.0.0.0',0))
								
								
								remoteudp = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
								
								client.send(sockudp.getsockname()[1].to_bytes(length=2,byteorder='big'))#发送绑定端口
								print('Bind in %d'% sockudp.getsockname()[1] )
								
								#test= sockudp.recvfrom(1024*100)
								
								#test=test[0]
								#test1=test[0]
								
								#backclient=test[1:test1+1]
								#backclient=backclient.decode()
								#backport=int.from_bytes(test[test1+1:], 'big')
								

								
								#print(int.from_bytes(sockudp.recvfrom(1), 'big'))
								#backclient=sockudp.revfrom(int.from_bytes(sockudp.recvfrom(1), 'big'))
								#backport=sockudp.recvfrom(2)
								#print(backclient)
								#print(backport)
								
								#print(sockudp.recvfrom(1).to_bytes(length=2,byteorder='big'))
								
								#sockudp.recvfrom()
								#backclient=sockudp.recvfrom(sockudp.recvfrom(1))
								#backport=sockudp.recvfrom(2)
								print("UDP-Hand-OK")
								
								
								#sockudp.sendto(b'\x03\x01',(backclient,backport) )
								
								try:
									fds = [sockudp,remoteudp,client]
									print(fds)
									while True:
										r,w,e = select.select(fds,[],[],1)
										#print(r)
										#print(w)
										#print(e)
										#if len(client.recv(1024))==0:
											#print('Tcp-Udp End')
											#break

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
												#copo=jibadate[0]*256+jibadate[1]
												cogpo = int.from_bytes(jibadate[0:2], 'big')
												print(cogpo)
												testdata = jibadate[2:]
												print(testdata)
												#lenddd = jibadate[0]
												lenddd=testdata[0]
												print(lenddd)
												ipoposad=testdata[1:1+lenddd]
												print(ipoposad)
												portoposad=testdata[1+lenddd]*256+testdata[2+lenddd]
												print(portoposad)
												testdata=testdata[3+lenddd:]
												
												#print(testdata)
												#lenddd=testdata[0]
												#sockdpp=testdata[1:1+lenddd]
												#testdata=testdata[3+lenddd:]
												#print(testdata)
												
												#testdata = sockudp.recvfrom(1024 * 100)
												udpdatein = testdata
												udpdatein = udpdatein[4:]
												ipgg=str(udpdatein[0]) +'\x2e'+ str(udpdatein[1]) +'\x2e'+ str(udpdatein[2]) + '\x2e'+ str(udpdatein[3])
												print(ipgg)
												portgg=udpdatein[4]*256+udpdatein[5]
												print(portgg)
												udpdatein=udpdatein[6:]
												remoteudp.sendto(udpdatein,(ipgg,portgg))
												

												#testdata = remoteudp.recvfrom(1024 * 100)
												#udpdateout = testdata[0]
												#lpo=testdata[1]
												#udpdateout = b'\x00\x00\x00\x01'+socket.inet_aton(lpo[0])+lpo[1].to_bytes(length=2,byteorder='big',signed=False)+udpdateout
												#coop= xorr(udpdateout)
												#sockudp.sendto(coop,('127.0.0.1',cogpo))
												
												#sockudp.sendto(coop,(backclient,backport))
											if i is remoteudp:
												print('web->server->client')
												udpdateout,lpo = remoteudp.recvfrom(1024 * 100)
												udpdateout = b'\x00\x00\x00\x01'+socket.inet_aton(lpo[0])+lpo[1].to_bytes(length=2,byteorder='big',signed=False)+udpdateout
												
												
												udpdateout = b'\x02'+len(ipoposad).to_bytes(1, byteorder = 'big')+ipoposad+portoposad.to_bytes(2, byteorder = 'big')+udpdateout
												
												coop= xorr(udpdateout)
												
												sockudp.sendto(coop,('127.0.0.1',port))
												
												
												#UDPsocked.sendto()
												
												
								except Exception as e:
									logging.error(e)
								finally:
									print('UDP Close Successfully')
									client.close()
									remoteudp.close()
									sockudp.close()
								
								#client.close()
								#sockudp.close()
								#remoteudp.close()
								
								#ttt=xorr(ooo[1:])
								
								
								
                                #if ooo[0]==1:
                                    #print('IP')
									#tempip=ttt[0:4]
									#remoteip= str(tempip[0]) +'\x2e'+ str(tempip[1]) +'\x2e'+ str(tempip[2]) + '\x2e'+ str(tempip[3])
									#remoteport = ttt[4]*256 + ttt[5]
									#mesg=ttt[6:]
									
									
								#if ooo[0]==3:
                                    #print('domain')
									#len=ttt[0]
									#yumingcode=data[1:2+len]
									
									
								


        #ver,methods = client.recv(1),client.recv(1)
        #methods = client.recv(ord(methods))
        #client.send(b'\x05\x00')

        #ver,cmd,rsv,atype = client.recv(1),client.recv(1),client.recv(1),client.recv(1)
        #if ord(cmd) is not 1:
            #client.close()
            #return


        # 判断是否支持atype，目前不支持IPv6
        # 比特流转化成整型 big表示编码为大端法，
        #if ord(atype) == 1:
            # IPv4
            #remote_addr = socket.inet_ntoa(client.recv(4))
            #remote_port = int.from_bytes(client.recv(2), 'big')
        #elif ord(atype) == 3:
            # 域名
            #addr_len = int.from_bytes(client.recv(1), byteorder = 'big')
            #remote_addr = client.recv(addr_len)
            #remote_port = int.from_bytes(client.recv(2), byteorder = 'big')
        #else:
            #不支持则关闭连接
            #client.close()
            #return
        #remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #logging.info('[+] %s:%dConnect to --> %s:%d' % (self.client_address[0], self.client_address[1], remote_addr, remote_port))
        #remote.connect((remote_addr, remote_port))

        #reply = b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + (2222).to_bytes(2, byteorder = 'big')

        #client.send(reply)


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
				#http.test()
				UDPshd = Process(target=TCP,)
				UDPshd.start()
				
				print("UDPrunning in :%d" % port)
				
				#global UDPsocked
				UDPserver = socketserver.ThreadingUDPServer((serverdd, port), UDPSocks5Server)
				UDPserver.serve_forever()
				

				print('[+] Lintening(UDP&TCP) on port:%d' % port)
				#TCP ()
				


				#print("[+] UDPrunning in :%d" % port)
				#UDPserver = socketserver.ThreadingUDPServer((serverdd, port), UDPSocks5Server)
				#UDPserver.serve_forever()






		except Exception as e:
				logging.error(e)
