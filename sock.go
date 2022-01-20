package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

var serverdd string
var port int
var pss string
var key1 int

func BytesCombine(pBytes ...[]byte) []byte {
	len := len(pBytes)
	s := make([][]byte, len)
	for index := 0; index < len; index++ {
		s[index] = pBytes[index]
	}
	sep := []byte("")
	return bytes.Join(s, sep)
}

func checkError(err error) bool {
	if err != nil {
		fmt.Println("Error:", err.Error())
		return true
	}
	return false
}
func typeof(v interface{}) {
	fmt.Printf("type is:%T\n", v)
}

func xor(data []byte) []byte {
	len := len(data)
	s := make([]byte, len)
	for index := 0; index < len; index++ {
		s[index] = uint8(int(data[index]) ^ key1)
	}
	return s
}

func Handle_TCP(Remote net.Conn, Local net.Conn) { //处理转发回来的数据
	var buffer = make([]byte, 128)
	for {
		n, err := Remote.Read(buffer)
		if err != nil {
			break
		}
		buffer = xor(buffer)
		n, err = Local.Write(buffer[:n])
		if err != nil {
			break
		}
	}
}

func Handle_conn(conn net.Conn) { //这个是在处理客户端会阻塞的代码。

	headerBuf := make([]byte, 128)
	_, err := conn.Read(headerBuf)
	if checkError(err) {
		return
	}

	type Fakejs struct {
		Fake string `json:"fake"`
	}

	if headerBuf[0] == 5 {
		conn.Write([]byte{5, 0})
	}

	_, err1 := conn.Read(headerBuf)
	if checkError(err1) {
		return
	}

	data := make([]byte, 2)

	//fmt.Println(headerBuf)
	if headerBuf[1] == 1 {
		if headerBuf[3] == 1 {

			data[0] = 1

			//fmt.Println(len(pss))
			data[1] = uint8(len(pss))
			data = BytesCombine(data, []byte(pss), []byte{2}, headerBuf[4:10])
			fmt.Printf("Connect to ip: %v.%v.%v.%v\n", headerBuf[4], headerBuf[5], headerBuf[6], headerBuf[7])
			//fmt.Println(data)
		}
		if headerBuf[3] == 3 {
			len1 := headerBuf[4]
			domain := headerBuf[5 : 5+len1]
			//doport := int(headerBuf[5+len1])*256 + int(headerBuf[6+len1])
			data[0] = 1
			data[1] = uint8(len(pss))
			data = BytesCombine(data, []byte(pss), []byte{1, len1}, xor(headerBuf[5:5+len1]), headerBuf[5+len1:7+len1])
			//fmt.Println(data)

			//fmt.Println(string(domain))
			fmt.Printf("Connect to domain: %v\n", string(domain))
			//fmt.Println(doport)
		}
		tcpAddr, err := net.ResolveTCPAddr("tcp", serverdd)
		if checkError(err) {
			return
		}
		myConn, err1 := net.DialTCP("tcp", nil, tcpAddr)
		if checkError(err1) {
			return
		}
		_, err = myConn.Write(data)
		if checkError(err) {
			return
		}
		_, err2 := myConn.Read(headerBuf)
		if checkError(err2) {
			return
		}
		if headerBuf[0] != 3 {
			fmt.Println("Connect Failed,Plase Check your network or ip is right")
			conn.Close()
			myConn.Close()
			return
		}

		conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 23, 176})
		go Handle_TCP(myConn, conn)
		var buffer = make([]byte, 128)
		for {
			n, err := conn.Read(buffer)
			if err != nil {
				break
			}
			buffer = xor(buffer)
			n, err = myConn.Write(buffer[:n])
			if err != nil {
				break
			}
		}
		conn.Close()
		myConn.Close()
	}
	if headerBuf[1] == 3 {
		fmt.Println("New UDP Connection!")
		//&net.UDPAddr{IP:   net.IPv4(127, 0, 0, 1),Port: 0,}
		UDPlistener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0})
		if checkError(err) {
			return
		}
		fmt.Println("Using Local UDP port:", UDPlistener.LocalAddr().(*net.UDPAddr).Port)

		if headerBuf[3] == 1 {
			tcpAddr, err := net.ResolveTCPAddr("tcp", serverdd)
			if checkError(err) {
				return
			}
			data[0] = 2
			data[1] = uint8(len(pss))
			data = BytesCombine(data, []byte(pss))

			myConn, err1 := net.DialTCP("tcp", nil, tcpAddr)
			if checkError(err1) {
				return
			}
			_, err = myConn.Write(data)
			if checkError(err) {
				return
			}
			_, err2 := myConn.Read(headerBuf)
			if checkError(err2) {
				return
			}
			_, err = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, uint8(UDPlistener.LocalAddr().(*net.UDPAddr).Port >> 8), uint8(UDPlistener.LocalAddr().(*net.UDPAddr).Port)})
			tempport := headerBuf[0:2]
			var replayport int
			for {
				data2 := make([]byte, 1024)
				//读取
				n, addr, err := UDPlistener.ReadFromUDP(data2)
				if checkError(err) {
					continue
				}
				//fmt.Println("接收的内容是：%v，来自地址：%v，字节数量：%v\n", string(data2[:n]), addr, n)
				if n == 0 {
					break
				}

				udpAddr, _ := net.ResolveUDPAddr("udp", serverdd)

				//fmt.Println(addr.IP.String()[0:3])
				if addr.Port != udpAddr.Port {
					replayport = addr.Port

					data2 = BytesCombine([]byte{1, uint8(len(pss))}, []byte(pss), tempport, data2)
					//fmt.Println(data2)
					data2 = xor(data2)
					fmt.Println("Send Data")

					_, err = UDPlistener.WriteToUDP(data2[:n+len(pss)+4], udpAddr)
					if checkError(err) {
						continue
					}

				} else {
					fmt.Println("Reveive Data")
					data2 = xor(data2)
					fmt.Println(data2)
					_, err = UDPlistener.WriteToUDP(data2[:n], &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: replayport})
					if checkError(err) {
						continue
					}
				}

			}

		}

	}

}

func udp_handle_server(addr string) { //UDP转发器
	udpAddr, _ := net.ResolveUDPAddr("udp", addr)
	UDPlistener, err := net.ListenUDP("udp", udpAddr)
	if checkError(err) {
		return
	}
	for {
		data2 := make([]byte, 1024)

		n, addr1, _ := UDPlistener.ReadFromUDP(data2)
		data2 = xor(data2)
		fmt.Printf("rec:%d bytes from %v\n", n, addr1)
		if data2[0] == 1 { //入站数据
			opp := data2[1]
			if string(data2[2:2+opp]) == pss {
				nowdate := data2[opp+2:]
				remote_port := uint64(nowdate[0])*256 + uint64(nowdate[1])
				datein := nowdate[2:]
				addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:"+fmt.Sprintf("%d", remote_port))
				data3 := []byte{0, 0, 1}
				data3[2] = uint8(len(addr1.IP))
				data3 = BytesCombine(data3, []byte(addr1.IP), []byte{uint8(addr1.Port >> 8), uint8(addr1.Port)}, datein[:n])
				//fmt.Println(data3, datein)
				UDPlistener.WriteToUDP(data3, addr2)
				//server11.sendto(server11.getsockname()[1].to_bytes(length=2,byteorder='big')+len(ccc[0]).to_bytes(1, byteorder = 'big')+bytes(ccc[0],encoding = "utf8")+ccc[1].to_bytes(2, byteorder = 'big')+datein,(('127.0.0.1'),remote_port))
			}
		} else if data2[0] == 2 { //转发回Client
			data2 = data2[:n]
			lena := data2[1]
			ipld := data2[2 : 2+lena]
			//portld := uint64(data2[2+lena])*256 + uint64(data2[3+lena])
			portld := uint64(ipld[lena-2])*256 + uint64(ipld[lena-1])
			date := data2[2+lena:]
			date = xor(date)
			fmt.Println(ipld)
			fmt.Println(data2[2+lena], data2[3+lena], lena, data2)
			fmt.Println(fmt.Sprintf("%d", ipld[0]) + "." + fmt.Sprintf("%d", ipld[1]) + "." + fmt.Sprintf("%d", ipld[2]) + "." + fmt.Sprintf("%d", ipld[3]) + ":" + fmt.Sprintf("%d", portld))
			addr2, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%d", ipld[0])+"."+fmt.Sprintf("%d", ipld[1])+"."+fmt.Sprintf("%d", ipld[2])+"."+fmt.Sprintf("%d", ipld[3])+":"+fmt.Sprintf("%d", portld))
			UDPlistener.WriteToUDP(date, addr2)
			//sockd.sendto(date,(ipld,portld))
		}
		fmt.Println(n, addr1)
	}

}
func UInt32ToIP(intIP uint32) net.IP {
	var bytes [4]byte
	bytes[0] = byte(intIP & 0xFF)
	bytes[1] = byte((intIP >> 8) & 0xFF)
	bytes[2] = byte((intIP >> 16) & 0xFF)
	bytes[3] = byte((intIP >> 24) & 0xFF)

	return net.IPv4(bytes[3], bytes[2], bytes[1], bytes[0])
}
func IPtoByte(IP net.IP) []byte {
	var bytes1 = make([]byte, 4)
	bits := strings.Split(IP.String(), ".")
	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])
	bytes1[0] = uint8(b0)
	bytes1[1] = uint8(b1)
	bytes1[2] = uint8(b2)
	bytes1[3] = uint8(b3)

	return bytes1
}

func Handle_conn_server(conn net.Conn) { //Server_mod

	headerBuf := make([]byte, 128)
	_, err := conn.Read(headerBuf)
	if checkError(err) {
		return
	}
	if headerBuf[0] == 1 {
		fmt.Println("TCPmod")

		if string(headerBuf[2:2+headerBuf[1]]) == pss {
			var myConn *net.TCPConn
			//myConn, err1 := net.DialTCP("tcp", nil, tcpAddr)
			fmt.Println("Password OK")
			if headerBuf[2+headerBuf[1]] == 1 {
				fmt.Println("Domain method")
				yumingcode := headerBuf[4+headerBuf[1] : 4+headerBuf[1]+headerBuf[headerBuf[1]+3]]
				yuming := xor(yumingcode)

				remoteport := uint64(headerBuf[4+headerBuf[1]+headerBuf[headerBuf[1]+3]])
				remoteport = remoteport*256 + uint64(headerBuf[5+headerBuf[1]+headerBuf[headerBuf[1]+3]])
				//ip1 := net.ParseIP()
				//addr1, _ := net.ResolveIPAddr("ip", string(yuming))
				//var addr2 *net.TCPAddr
				//addr2.IP = addr1.IP
				//addr2.Port = int(remoteport)
				addr2, _ := net.ResolveTCPAddr("tcp", string(yuming)+":"+fmt.Sprintf("%d", remoteport))
				//typeof(addr1)
				myConn, _ = net.DialTCP("tcp", nil, addr2)
				fmt.Println(yuming, string(yuming), remoteport, addr2.IP)
			} else {
				tempip := headerBuf[3+headerBuf[1] : 7+headerBuf[1]]
				//var addr1 *net.TCPAddr

				//addr1.IP = net.IPv4(headerBuf[0], headerBuf[1], headerBuf[2], headerBuf[3])
				remoteport := uint64(headerBuf[7+headerBuf[1]])*256 + uint64(headerBuf[8+headerBuf[1]])
				fmt.Println(remoteport)
				//var addr2 *net.TCPAddr
				//addr2.IP = addr1.IP
				//addr2.Port = int(remoteport)
				addr2, _ := net.ResolveTCPAddr("tcp", string(tempip)+":"+fmt.Sprintf("%d", remoteport))
				myConn, _ = net.DialTCP("tcp", nil, addr2)
				//net.IPAddr.IP addr1 = tetempip

			}
			conn.Write([]byte{3, 0})

			go Handle_TCP(myConn, conn)
			var buffer = make([]byte, 128)
			for {
				n, err := conn.Read(buffer)
				if err != nil {
					break
				}
				buffer = xor(buffer)
				n, err = myConn.Write(buffer[:n])
				if err != nil {
					break
				}
			}

			//var test *net.TCPAddr
			//test.IP=addr1.IP

			//tcpAddr, err := net.ResolveTCPAddr("tcp", serverdd)
			//if checkError(err) {
			//	return
			//}

		}
	}
	if headerBuf[0] == 2 {
		fmt.Println("UDPmod")

		if string(headerBuf[2:2+headerBuf[1]]) == pss {
			UDPlistener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0})
			if checkError(err) {
				return
			}
			_, err = conn.Write([]byte{uint8(UDPlistener.LocalAddr().(*net.UDPAddr).Port >> 8), uint8(UDPlistener.LocalAddr().(*net.UDPAddr).Port)})
			fmt.Printf("Server Bind in port:%v", UDPlistener.LocalAddr())

			//tempport := headerBuf[0:2]
			var replayport int
			var ipoposad []byte
			//portoposad := uint64(0)
			for {
				data2 := make([]byte, 1024)
				//读取
				n, addr, err := UDPlistener.ReadFromUDP(data2)
				if checkError(err) {
					continue
				}
				//fmt.Println("接收的内容是：%v，来自地址：%v，字节数量：%v\n", string(data2[:n]), addr, n)
				if n == 0 {
					break
				}

				udpAddr, _ := net.ResolveUDPAddr("udp", serverdd)

				//fmt.Println(addr.IP.String()[0:3])
				//if addr.Port != udpAddr.Port {

				//portoposad = 0
				fmt.Println(addr.IP, "this", addr.IP.String(), n)
				if addr.IP.String() == "127.0.0.1" {
					fmt.Println("Reveive Data from client")
					replayport = addr.Port
					data2 = data2[:n]
					testdata := data2[2:]
					lenddd := testdata[0]
					ipoposad = testdata[1 : 1+lenddd+2]
					//portoposad = uint64(testdata[1+lenddd])*256 + uint64(testdata[2+lenddd])

					testdata = testdata[3+lenddd:]
					udpdatein := testdata
					udpdatein = udpdatein[4:]
					ipgg := fmt.Sprintf("%d", udpdatein[0]) + "." + fmt.Sprintf("%d", udpdatein[1]) + "." + fmt.Sprintf("%d", udpdatein[2]) + "." + fmt.Sprintf("%d", udpdatein[3])
					portgg := uint64(udpdatein[4])*256 + uint64(udpdatein[5])
					udpdatein1 := udpdatein[6:]
					fmt.Println(ipgg + ":" + fmt.Sprintf("%d", portgg))
					addr2, _ := net.ResolveUDPAddr("udp", ipgg+":"+fmt.Sprintf("%d", portgg))
					UDPlistener.WriteToUDP(udpdatein1, addr2)

					//data2 = BytesCombine([]byte{1, uint8(len(pss))}, []byte(pss), tempport, data2)
					//fmt.Println(data2)
					//data2 = xor(data2)
					//fmt.Println("Send Data")

					_, err = UDPlistener.WriteToUDP(data2, udpAddr)
					if checkError(err) {
						continue
					}

				} else {
					fmt.Println("Reveive Data from remote")
					udpdateout := BytesCombine([]byte{0, 0, 0, 1}, IPtoByte(addr.IP), []byte{uint8(addr.Port >> 8), uint8(addr.Port)}, data2[:n])
					data0 := []byte{2, 0}
					data0[1] = uint8(len(ipoposad))

					udpdateout = BytesCombine(data0, ipoposad, udpdateout)
					data2 = xor(udpdateout)
					_, err = UDPlistener.WriteToUDP(data2[:n], &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: replayport})
					if checkError(err) {
						continue
					}
				}

			}

		}
	}

}

func main() {
	addr := "127.0.0.1:6064"
	mod := "server"
	//serverdd = "127.0.0.1:9997"
	//pss = "000"
	//fmt.Println(os.Args)
	flag.StringVar(&addr, "l", "127.0.0.1:6064", "Client:Local Address 127.0.0.1:port")
	flag.StringVar(&serverdd, "c", "127.0.0.1:9997", "Client:Connect to Server server:port/Server:bind Address")
	flag.StringVar(&pss, "k", "000", "password connect to server")
	flag.StringVar(&mod, "m", "server", "server mod/Client mod")
	flag.Parse()

	//key1 = 48
	key1 = int(pss[1])

	if mod != "server" {
		fmt.Printf("bind Local Server in %v connect to %v ,password set:%v\n", addr, serverdd, pss)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatal(err)
		}
		defer listener.Close()

		for {
			conn, err := listener.Accept() //用conn接收链接
			if err != nil {
				log.Fatal(err)
			}
			go Handle_conn(conn)
		}
	} else {
		fmt.Printf("Listen Server in %v ,password set:%v\n", serverdd, pss)
		go udp_handle_server(serverdd)
		listener, err := net.Listen("tcp", serverdd)
		if err != nil {
			log.Fatal(err)
		}
		defer listener.Close()

		for {
			conn, err := listener.Accept() //用conn接收链接
			if err != nil {
				log.Fatal(err)
			}
			go Handle_conn_server(conn)
		}
	}
	//fmt.Print("123")
}
