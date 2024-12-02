package main

import (
	"encoding/binary"
	"flag"
	"log"
	"net"
	"syscall"

	"golang.org/x/net/ipv4"
)

func main() {
	// 源端口和目标端口
	srcPort := 12345
	dstPort := 80

	flag.IntVar(&srcPort, "srcPort", 12345, "src port")
	flag.IntVar(&dstPort, "dstPort", 80, "dst port")

	sa := flag.String("srcAddr", "127.0.0.1", "src addr")
	da := flag.String("dstAddr", "127.0.0.1", "dst addr")

	syn := flag.Bool("syn", true, "syn flag")
	ack := flag.Bool("ack", false, "ack flag")
	fin := flag.Bool("fin", false, "fin flag")
	rst := flag.Bool("rst", false, "rst flag")
	psh := flag.String("psh", "", "push data")

	seqn := flag.Uint("seqn", 1, "sequence number")
	ackn := flag.Uint("ackn", 1, "acknowledgment number")

	ipId := flag.Int("ipID", 0, "ipv4 identification")

	flag.Parse()

	// 源IP和目标IP
	srcIP := net.ParseIP(*sa).To4()
	dstIP := net.ParseIP(*da).To4()

	flags := 0x00
	if *syn {
		flags |= 0x02
	}
	if *ack || *ackn > 1 {
		flags |= 0x10
	}
	if *fin {
		flags |= 0x01
	}
	if *rst {
		flags |= 0x04
	}

	payload := []byte(*psh)
	payloadSize := len(payload)
	if payloadSize > 0 {
		flags |= 0x08
	}

	// 创建原始套接字
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatalf("Socket creation failed: %v", err)
	}
	defer syscall.Close(fd)

	// 设置套接字选项，以便我们可以自己构造 IP 头部
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		log.Fatalf("SetsockoptInt failed: %v", err)
	}

	// 构造IP头
	ipHeader := &ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: 40 + payloadSize,
		ID:       *ipId,
		Flags:    ipv4.DontFragment,
		TTL:      64,
		Protocol: syscall.IPPROTO_TCP,
		Src:      srcIP,
		Dst:      dstIP,
	}

	// 构造TCP头
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(tcpHeader[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(tcpHeader[4:8], uint32(*seqn))  // Sequence number
	binary.BigEndian.PutUint32(tcpHeader[8:12], uint32(*ackn)) // Acknwledgment number
	tcpHeader[12] = 5 << 4                                     // Data offset
	tcpHeader[13] = byte(flags)                                // Flags ack:0x10 syn:0x2
	binary.BigEndian.PutUint16(tcpHeader[14:16], 6379)         // Window size
	binary.BigEndian.PutUint16(tcpHeader[16:18], 0)            // Checksum (initially 0)
	binary.BigEndian.PutUint16(tcpHeader[18:20], 0)            // Urgent pointer

	// 计算TCP校验和
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP)
	copy(pseudoHeader[4:8], dstIP)
	pseudoHeader[8] = 0
	pseudoHeader[9] = syscall.IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(tcpHeader)+payloadSize))
	pseudoHeader = append(pseudoHeader, tcpHeader...)
	pseudoHeader = append(pseudoHeader, payload...)
	checksum := checksum(pseudoHeader)
	binary.BigEndian.PutUint16(tcpHeader[16:18], checksum)

	// 构造完整的包
	packet, err := ipHeader.Marshal()
	if err != nil {
		log.Fatalf("IP header marshal failed: %v", err)
	}
	packet = append(packet, tcpHeader...)
	if payloadSize > 0 {
		packet = append(packet, payload...)
	}

	log.Println("packet: ", packet)

	// 发送包
	addr := syscall.SockaddrInet4{
		Port: dstPort,
		Addr: [4]byte{dstIP[0], dstIP[1], dstIP[2], dstIP[3]},
	}
	if err := syscall.Sendto(fd, packet, 0, &addr); err != nil {
		log.Fatalf("Sendto failed: %v", err)
	}

	log.Println("TCP packet sent successfully")
}

// 计算校验和
func checksum(data []byte) uint16 {
	sum := 0
	for i := 0; i < len(data)-1; i += 2 {
		sum += int(data[i])<<8 | int(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += int(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum)
}
