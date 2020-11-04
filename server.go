package main

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "log"
    "time"
    "net"
    "strings"
    "strconv"
)

var (
    device       string = "lo"
    snapshot_len int32  = 1024
    promiscuous  bool   = false
    err          error
    timeout      time.Duration = -1 * time.Second
    handle       *pcap.Handle
)

func main() {
	ch := make(chan []byte)
	go handleMessageRead(ch)
	
    // Open device
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

    // Set filter
    var filter string = "udp and port 3000"
    err = handle.SetBPFFilter(filter)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Only capturing UDP port 3000 packets.")

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
	    // Do something with a packet here.
	    fmt.Println(packet.Data())
	    
	    rawBytes := packet.Data()
	    
	    ethHeader :=  rawBytes[:14]

	    //Length of ipHeader in 4 byte words
	    ipLen := rawBytes[14] & 0b1111
	    ipEndIndex := 14 + (4 * ipLen)
	    ipHeader := rawBytes[14:ipEndIndex]

	    udpEndIndex := ipEndIndex + 8
	    udpHeader := rawBytes[ipEndIndex:udpEndIndex]
	    payload := rawBytes[udpEndIndex:]


	    csum := combine_uint16(udpHeader[6], udpHeader[7])

	    fmt.Println(ethHeader)
	    fmt.Println(ipHeader)
	    fmt.Println(udpHeader)
	    fmt.Println(payload)
	    fmt.Println("\n")
	    fmt.Println("Original checksum:")
	    fmt.Println(csum)
	    fmt.Println("\n")
	    

	    //Attempt to hide message in payload and retransmit packet
	    
	    udpHeader = []byte{11, 184, 31, 144, 0, 0, 0, 0}
	    ipHeader = []byte{69, 0, 0, 61, 175, 205, 64, 0, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1}

	    msgStr := <- ch
	    message := []byte(msgStr)
	    newPayload := hideMessage(payload, message)
	    packet := append(udpHeader, newPayload...)
	    length := uint16(len(packet))
	    high, low := split_uint16(length)

	    udpHeader[4] = high
	    udpHeader[5] = low

	    packet = append(append(ipHeader, udpHeader...), newPayload...)
	    length = uint16(len(packet))
	    high, low = split_uint16(length)

	    ipHeader[2] = high
	    ipHeader[3] = low

	    psuedoHeader = append(ipHeader[12:], 17)
	    psuedoHeader = append(psuedoHeader, ipHeader[3:5]...)
	    
	    data = append(udpHeader, newPayload...)
	    checksum = udpChecksum(psuedoHeader, data)
	    high, low = split_uint16(checksum)

	    fmt.Println("New checksum:")
	    fmt.Println(checksum)

	    udpHeader[6] = high
	    udpHeader[7] = low

	    checksum = ipChecksum(ipHeader)
	    high, low = split_uint16(checksum)

	    ipHeader[10] = high
	    ipHeader[11] = low

	    packet = append(ethHeader, append(append(ipHeader, udpHeader...), newPayload...)...)
	    fmt.Println("New packet:")
	    fmt.Println(packet)
	    fmt.Println("Payload in string form:")
	    fmt.Println(string(newPayload))
	    
    }

}

func handleMessageRead(c chan []byte) {
	//Normal udp server to listen for message to hide sent by client
	msg, err := listenUDPMessage(6000)
	if err != nil {
		fmt.Println("Problem reading message from client")
		return
	}
	c <- msg
}

func listenUDPMessage(port int) ([]byte, error) {
	p := make([]byte, 2048)
	addr := net.UDPAddr{
		Port: port,
		IP: net.ParseIP("127.0.0.1"),
	}
	ser, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return nil, err
	}
	for {
		_,remoteaddr,err := ser.ReadFromUDP(p)
		fmt.Printf("Read a message from %v %s \n", remoteaddr, p)
		if err !=  nil {
			return nil, err
		}
		return p, nil
	}
}


func udpChecksum(phdr []byte, data []byte) uint16 {
	//compute 16 bit sum of pseudoheader and data. Data consists of udp header and payload
	var sum32 uint32 = sum16(data) + sum16(phdr)

	//convert uint32 to uint16 by repeatedly adding carries
	for i := 0; sum32 > 65535; i++{
		sum32 = ((sum32 & (((1 << 16) - 1) << 16) ) >> 16) + (sum32 & ((1 << 16) - 1))
	}
	//fmt.Printf("%x\n", sum32)
	//fmt.Printf("%d", ^uint16(sum32))
	//return inverse of this 16 bit sum
	return ^uint16(sum32)
}

func ipChecksum(header []byte) uint16 {
	var sum32 uint32 = sum16(header)

	//convert uint32 to uint16 by repeatedly adding carries
	for i := 0; sum32 > 65535; i++{
		sum32 = ((sum32 & (((1 << 16) - 1) << 16) ) >> 16) + (sum32 & ((1 << 16) - 1))
	}
	
	return ^uint16(sum32)
}

//Sums the values in an array of bytes as 16 bit unsigned integers and returns the result as
//an unsigned 32 bit integer
func sum16(arr []byte) uint32{
	var sum uint32 = 0
	for i := 0; i < len(arr); i += 2{
		b1 := uint16(arr[i])
		var b2 uint16
		if (i + 1) >= len(arr) {
			b2 = 0
		}else {
			b2 = uint16(arr[i + 1])
		}
		
		var twoByte uint16 = (b1 << 8) + b2
		sum += uint32(twoByte)
	}
	return sum
}

//combines 2 equally sized bytes to form a 16 bit integer
func combine_uint16(high byte, low byte) (uint16) {
        num := (uint16(high)*256) + uint16(low)
	return num
}

//splits a 16 bit unsigned integer into two equally sized bytes
func split_uint16(num uint16) (byte, byte) {
	high := byte((num & (((1 << 8) - 1) << 8)) >> 8) //upper 8 bits
	low := byte(num & ((1 << 8) - 1)) //lower 8 bits
	return high, low
}

//hide message in prvided payload data
func hideMessage(data []byte, msg []byte) []byte {
	dataBinStr := stringToBin(string(data))
	msgBinStr := stringToBin(string(msg))
	
	rand.Seed(1111)
	numBits := len(msgBinStr)
	var randPositions = make([]int, numBits, numBits)
	
	for i := 0; i < numBits; i++ {
		randIndex := rand.Intn(len(dataBinStr) + i)
		randPositions[i] = randIndex
	}
	sort.Ints(randPositions)
	fmt.Println(randPositions)
	
	newStr := dataBinStr
	for i := 0; i < numBits; i++ {
		currentBit := msgBinStr[i:i+1]
		newStr = insertBit(newStr, currentBit, randPositions[i])
	}
	fmt.Println("hidden binary: " + newStr)
	return []byte(binToString(newStr))
}

//extract hidden message from payload
func extractMessage(data []byte, msgLen int) (extractedMsg []byte, origData []byte) {
	dataBinStr := stringToBin(string(data))
	fmt.Println(dataBinStr)
	numBits := msgLen * 8
	rand.Seed(1111)
	
	var randPositions = make([]int, numBits, numBits)
	
	for i := 0; i < numBits; i++ {
		randIndex := rand.Intn(len(dataBinStr) - numBits + i)
		randPositions[i] = randIndex
	}
	sort.Ints(randPositions)

	newStr := dataBinStr
	msgBin := ""
	for i := 0; i < numBits; i++ {
		bit, altered := extractBit(newStr, randPositions[i] - i)
		newStr = altered
		msgBin += bit
	}
	return []byte(binToString(msgBin)), []byte(binToString(newStr))
}

//insert a bit into a bit string at given index
func insertBit(bStr string, bit string, index int) string {
	return bStr[:index] + bit + bStr[index:]
}

//remove single bit from bit string at given index
func extractBit(data string, index int) (bit string, newStr string) {
	newStr = data[:index+1] + data[index + 2:]
	return data[index+1:index+2], newStr
}

//convert readable ascii string to bit string
func stringToBin(s string) (binString string) {
    for _, c := range s {
        binString = fmt.Sprintf("%s%.8b",binString, c)
    }
    return 
}

//convert a bit string to readable ascii string
func binToString(s string) (str string) {
	b := make([]byte, 0)
	for i := 0; i < len(s); i += 8 {
		n, _ := strconv.ParseUint(s[i:i+8], 2, 8)
		b = append(b, byte(n))
	}
	return string(b)
}
