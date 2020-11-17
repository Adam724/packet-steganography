package main

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "log"
    "time"
    "math/rand"
    "sort"
    "strconv"
    "net"
    "bufio"
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
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	var filter string = "udp and port 3001"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Only capturing UDP port 3001 packets.")

	var message []byte
	var totalLength uint16
	var destPort uint16
	var destIP []byte
	var headerExtracted bool = false
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println("Packet received!")
		rawBytes := packet.Data()
	    
		//ethHeader :=  rawBytes[:14]

		//Length of ipHeader in 4 byte words
		ipLen := rawBytes[14] & 0b1111
		ipEndIndex := 14 + (4 * ipLen)
		//ipHeader := rawBytes[14:ipEndIndex]

		udpEndIndex := ipEndIndex + 8
		//udpHeader := rawBytes[ipEndIndex:udpEndIndex]
		payload := rawBytes[udpEndIndex:]

		mLen := uint16(payload[len(payload) - 1])
		payload = payload[:len(payload) - 1]
		
		extractedFragment, originalPayload := extractMessage(payload, mLen, true)
		message = append(message, extractedFragment)
		if len(message) > 7 && !headerExtracted {
			fmt.Println(message)
			destPort  = (uint16(message[0]) << 8) + uint16(message[1])
			destIP = message[2:6]
			totalLength = (uint16(message[6]) << 8) + uint16(message[7])
			headerExtracted = true
			fmt.Printf("Original destination port: %d\n", destPort)
			fmt.Println("Original destination ip: ", destIP)
			fmt.Println("Total message length: ", totalLength)
		}
		//fmt.Println(extractedFragment)
		//fmt.Println("Original payload in string format: ", string(originalPayload))

		if headerExtracted && uint16(len(message)) >= totalLength {
			fmt.Println("Full message received!")
			fmt.Println(string(message))
			message = make([]byte, 0)
			headerExtracted = false
		}

		//Send original payload to original destination port
		go sendMessage(string(originalPayload), destPort)
		
		
	}
}

//extract hidden message from payload
func extractMessage(data []byte, msgLen uint16, setSeed bool) (extractedMsg []byte, origData []byte) {
	dataBinStr := bytesToBin(data)
	numBits := int(msgLen) * 8
	if setSeed {
		rand.Seed(1111)
	}
	
	var randPositions = make([]int, numBits, numBits)
	
	for i := 0; i < numBits; i++ {
		randIndex := rand.Intn(len(dataBinStr) - numBits + i)
		randPositions[i] = randIndex
	}
	sort.Ints(randPositions)

	newStr := dataBinStr
	msgBin := ""
	for i := numBits - 1; i >= 0; i-- {
		//fmt.Printf("%s, ", newStr)
		bit, altered := extractBit(newStr, randPositions[i])
		newStr = altered
		msgBin = bit + msgBin
		//fmt.Printf("%d, %s\n", randPositions[i], bit)
	}
	return binToBytes(msgBin), binToBytes(newStr)
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

func sendMessage(msg string, port uint16) {
	p :=  make([]byte, 2048)
	conn, err := net.Dial("udp", "127.0.0.1:" + strconv.Itoa(int(port)))
	if err != nil {
		//return err
		fmt.Println(err)
	}
	fmt.Fprintf(conn, msg)
	_, err = bufio.NewReader(conn).Read(p)
	if err == nil {
		fmt.Printf("%s\n", p)
	} else {
		//return err
		fmt.Println(err)
	}
	conn.Close()
	//return nil
}

//combines 2 equally sized bytes to form a 16 bit integer
func combine_uint16(high byte, low byte) (uint16) {
        num := (uint16(high)*256) + uint16(low)
	return num
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
