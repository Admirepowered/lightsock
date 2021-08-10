package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net"
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
	var buffer = make([]byte, 1024)
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
		var buffer = make([]byte, 1024)
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
	//serverdd = "127.0.0.1:9997"
	//pss = "000"
	//fmt.Println(os.Args)
	flag.StringVar(&addr, "l", "127.0.0.1:6064", "Local Address 127.0.0.1:port")
	flag.StringVar(&serverdd, "c", "127.0.0.1:9997", "Connect to Server server:port")
	flag.StringVar(&pss, "k", "000", "password connect to server")
	flag.Parse()
	fmt.Printf("bind Local Server in %v connect to %v ,password set:%v\n", addr, serverdd, pss)
	//key1 = 48
	key1 = int(pss[1])

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

	//fmt.Print("123")
}
