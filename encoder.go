package main

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "log"
    "time"
    "net"
    "math/rand"
    "sort"
    "errors"
	"strconv"
	"math"
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
	fmt.Println("Only capturing UDP port 3000 packets.\n")
	message := make([]byte, 10000)
	var i int = 0
	var end int = 0
	var high byte
	var low byte
	var fragment []byte
	var header []byte
	var customPacket []byte

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
	    // Do something with a packet here.
	    sequenceNumber := i
	    if i == 0 {
		    select {
		    case message = <-ch:
			    header = make([]byte, 0)
			    mode := int(message[0])
			    //fmt.Println("mode: ", mode)
			    message = message[1:]
			    //create and append custom header with original destination port and ip to the message
			    high, low = split_uint16(3003)
			    destPort := []byte{high, low}
			    destIP := []byte{127, 0, 0, 1}
			    high, low = split_uint16(uint16(len(message)))
			    totalLength := []byte{high, low}
			    header = append(totalLength, header)
			    header = append(destIP, header)
			    header = append(destPort, header)
			    header = appendOne(header, byte(0))
			    header = appendOne(header, byte(mode))
			    fmt.Println("\nCustom Header:")
			    fmt.Println(header)
			    fmt.Println("\n")
		    default:
			    fmt.Println("no message received")
			    return
		    }
	    }else{
		header[8] = byte(i)
	    }
	    
	    rawBytes := packet.Data()
		    
	    
	    ethHeader :=  rawBytes[:14]

	    //Length of ipHeader in 4 byte words
	    ipLen := rawBytes[14] & 0b1111
	    ipEndIndex := 14 + (4 * ipLen)
	    ipHeader := rawBytes[14:ipEndIndex]

	    udpEndIndex := ipEndIndex + 8
	    udpHeader := rawBytes[ipEndIndex:udpEndIndex]
	    payload := rawBytes[udpEndIndex:]

	    //determine how much of the message we can fit in this packet
	    end = int(math.Ceil(float64(len(payload)) * float64(0.3))) - 10
	    var bytesSent int
	    if end < 1 {
		    //not enough space to fit any part of message with 9 byte header, so set minimum amount that can be hidden to 8 bytes (18 bytes in total with header
		    fragment = message[:8]
		    message = message[8:]
		    bytesSent = 8
	    } else if len(message) <= end {
		    fragment = message
		    end = 0
		    i = -1
		    bytesSent = len(fragment)
		    message = make([]byte, 0)
	    }else{
		    fragment = message[:end]
		    message = message[end:]
		    bytesSent = end
	    }

	    customPacket = append(header, fragment)
	    
	    newPayload, err := hideMessage(payload, customPacket)
	    if err != nil {
		fmt.Println(err)
		return
	    }

	    //change destination port to 3001, where decoder.go will pick it up
	    udpHeader[3] = 185
	    packet := append(udpHeader, newPayload)
	    length := uint16(len(packet))
	    high, low = split_uint16(length)

	    udpHeader[4] = high
	    udpHeader[5] = low


	    packet = append(append(ipHeader, udpHeader), newPayload)
	    length = uint16(len(packet))
	    high, low = split_uint16(length)

	    ipHeader[2] = high
	    ipHeader[3] = low

	    psuedoHeader := appendOne(ipHeader[12:], 17)
	    psuedoHeader = append(psuedoHeader, ipHeader[3:5])
	    
	    data := append(udpHeader, newPayload)
	    checksum := udpChecksum(psuedoHeader, data)
	    high, low = split_uint16(checksum)

	    udpHeader[6] = high
	    udpHeader[7] = low

	    checksum = ipChecksum(ipHeader)
	    high, low = split_uint16(checksum)

	    ipHeader[10] = high
	    ipHeader[11] = low

	    packet = append(ethHeader, append(append(ipHeader, udpHeader), newPayload))
	    //fmt.Println("New packet:")
	    //fmt.Println(packet)

	    
	    fmt.Printf("***Packet with sequence number %d***\n", sequenceNumber)
	    fmt.Println("Original Payload:")
	    fmt.Println(string(payload))
	    fmt.Printf("\n")
	    fmt.Printf("New payload with %d bytes of message embedded:\n", bytesSent)
	    fmt.Println(string(newPayload))
	    fmt.Println("------------------------------------------\n")
	    
	    if i == -1 {
	       fmt.Println("Full Message has been sent.\n")
	    }
	    

	    err = handle.WritePacketData(packet)
	    if err != nil {
		    log.Fatal(err)
	    }
	    
	    
	    i++
    }

}

func handleMessageRead(c chan []byte) {
	//Normal udp server to listen for message to hide sent by client
	err := listenUDPMessage(6000, c)
	if err != nil {
		fmt.Println("Problem reading message from client")
		return
	}
	
}

func listenUDPMessage(port int, c chan []byte) (error) {
	p := make([]byte, 10000)
	addr := net.UDPAddr{
		Port: port,
		IP: net.ParseIP("127.0.0.1"),
	}
	ser, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return err
	}
	for {
		l,remoteaddr,err := ser.ReadFromUDP(p)
		fmt.Printf("Read a message from %v %s, length: %d \n", remoteaddr, p, l)
		if err !=  nil {
			continue
		}
		c <- p[:l]
	}
}


func udpChecksum(phdr []byte, data []byte) uint16 {	//compute 16 bit sum of pseudoheader and data. Data consists of udp header and payload
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

//hide message in provided payload data, append message length to end as single byte. This is necessary for extraction
func hideMessage(data []byte, msg []byte) ([]byte, error) {
	if len(msg) * 2 > len(data) {
		return nil, errors.New("Message is too large to hide in this payload")
	}
	dataBinStr := bytesToBin(data)
	msgBinStr := bytesToBin(msg)
	
	rand.Seed(1111)
	numBits := len(msgBinStr)
	var randPositions = make([]int, numBits, numBits)
	
	for i := 0; i < numBits; i++ {
		randIndex := rand.Intn(len(dataBinStr) + i)
		randPositions[i] = randIndex
	}
	sort.Ints(randPositions)
	
	newStr := dataBinStr
	for i := 0; i < numBits; i++ {
		//fmt.Printf("%s, ", newStr)
		currentBit := msgBinStr[i:i+1]
		newStr = insertBit(newStr, currentBit, randPositions[i])
		//fmt.Printf("%d, %s\n", randPositions[i], currentBit)
	}
	return appendOne(binToBytes(newStr), byte(len(msg))), nil
}

//insert a bit into a bit string at given index
func insertBit(bStr string, bit string, index int) string {
	return bStr[:index+1] + bit + bStr[index+1:]
}

//remove single bit from bit string at given index
func extractBit(data string, index int) (bit string, newStr string) {
	newStr = data[:index+1] + data[index + 2:]
	return data[index+1:index+2], newStr
}

//convert readable ascii string to bit string
func bytesToBin(b []byte) (binString string) {
    for _, c := range b {
        binString = fmt.Sprintf("%s%.8b", binString, c)
    }
    return 
}

//convert a bit string to readable ascii string
func binToBytes(s string) []byte {
	b := make([]byte, 0)
	for i := 0; i < len(s); i += 8 {
		n, _ := strconv.ParseUint(s[i:i+8], 2, 8)
		b = appendOne(b, byte(n))
	}
	return b
}

//manual append function to combine two byte arrays for verilog compiler
func append(arr1 []byte, arr2 []byte) []byte {
	arr1Len := len(arr1)
	newLen := len(arr1) + len(arr2)
	result := make([]byte, newLen)
	
	for i:= 0; i < arr1Len; i++ {
		result[i] = arr1[i]
	}
	
	for i := 0; i < len(arr2); i++ {
		result[i + arr1Len] = arr2[i]
	}
	return result
}

//appends single byte to byte array in verilog-compiler safe way
func appendOne(arr1 []byte, oneByte byte) []byte {
	result := make([]byte, len(arr1) + 1)
	for i:= 0; i < len(arr1); i++ {
		result[i] = arr1[i]
	}
	result[len(result) - 1] = oneByte
	return result
}
