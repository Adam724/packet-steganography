package main

import (
	"github.com/google/gopacket/pcap"
	"fmt"
	"log"
	"time"
	"os"
	"net"
	"bufio"
	"math"
	"image/jpeg"
	"bytes"
	"image"
)

var (
    device       string = "lo" //loopback device, for local testing
    snapshot_len int32  = 1024
    promiscuous  bool   = false
    err          error
    timeout      time.Duration = -1 * time.Second
    handle       *pcap.Handle
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Please specify a mode:\n-m to send a message\n-i to send an image\n\nAnd context:\nA message\nA path to an image\n")
		return
	}
	var mode int
	var message []byte

	//client wants to send a text message
	if os.Args[1] == "-m" {
	   message = []byte(os.Args[2])
	   mode = 1
	}else if os.Args[1] == "-i" { //client wants to send an image
		mode = 2

		//Open specified image file
		file, err := os.Open(os.Args[2])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		defer file.Close()

		//Read the image file and get image object
		img, _, err := image.Decode(bufio.NewReader(file))
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		//buffer to hold raw bytes of image
		buf := new(bytes.Buffer)
		err = jpeg.Encode(buf, img, nil)
		message = buf.Bytes()

	}else{
	   fmt.Println("Please specify a mode from the options below:\n-m to send a message\n-i to send an image")
	   return
	}
	
	fmt.Println("\nMessage inputted succesfully, length: ", len(message))

	//synchronous function to send the message (raw image bytes or ascii message) to encoder.go
	go handleMessageSend(message, mode)
	fmt.Println("Message has been sent to encoder.")
	
	//-----Generate packets to hide message in and send them to encoder.go-----
	
	// Open device to eventually send packets
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {log.Fatal(err) }
	defer handle.Close()

	//contents of dummy packets, longer payloads will allow for larger portions of the message to be hidden in them
	payload := []byte("this is a test message for steganography blah blah blah")
	
	ethHeader := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0}

	//version: 4, header length(in 4 byte words): 5, TOS: 0, Length: ?, identifier: ?, flags: 4,
	//offset: 0, TTL: 64, protocol: 17 (udp), checksum: ?, srcIP: 127.0.0.1, dstIP: 127.0.0.1
	ipHeader := []byte{69, 0, 0, 61, 175, 205, 64, 0, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1}

	//srcPort: 3000, dstPort: 8080, length: ?, checksum: ?
	//udpHeader := []byte{11, 184, 31, 144, 0, 0, 0, 0}
	udpHeader := []byte{31, 144, 11, 184, 0, 0, 0, 0}

	//combine udp header and payload and get length
	packet := append(udpHeader, payload)
	length := uint16(len(packet))
	high, low := split_uint16(length)

	//set length field in udp header
	udpHeader[4] = high
	udpHeader[5] = low
	
	//append ip header to front of packet and get length
	packet = append(append(ipHeader, udpHeader), payload)
	length = uint16(len(packet))
	high, low = split_uint16(length)

	//set length field in ip header
	ipHeader[2] = high
	ipHeader[3] = low

	//pseudoHeader for udp checksum. srcIP, dstIP, protocol, length
	pseudoHeader := appendOne(ipHeader[12:], byte(0))
	pseudoHeader = appendOne(pseudoHeader, byte(17))
	pseudoHeader = append(pseudoHeader, udpHeader[4:6])

	//calculate and set udp checksum
	data := append(udpHeader, payload)
	csum := sum16(pseudoHeader)
	checksum := calcChecksum(csum, data)
	high, low = split_uint16(checksum)
	udpHeader[6] = high
	udpHeader[7] = low

	//calculate and set ip header checksum
	checksum = calcChecksum(0, ipHeader)
	high, low = split_uint16(checksum)
	ipHeader[10] = high
	ipHeader[11] = low

	//all header fields have been calculated/populated, so reconstruct full packet
	packet = append(ethHeader, append(append(ipHeader, udpHeader), payload))

	//the maximum percentage by which each packet's payload length will be increased by before hiding the next part of the message in a new packet
	var capacity float64 = 0.3

	//determine how much of the message can be hidden in the dummy packet (not including 11 byte header), minimum 8 bytes
	var maxMsgLen int = int(math.Ceil(float64(len(payload)) * capacity)) - 11
	if maxMsgLen < 8 {
		maxMsgLen = 8
	}

	//calculate how many dummy packets must be sent to encoder.go
	var numPackets int = int(math.Ceil(float64(len(message)) / float64(maxMsgLen)))

	//send correct number of packets to encoder.go
	for i := 0; i < numPackets; i++ {
		err = handle.WritePacketData(packet)
		if err != nil {
			log.Fatal(err)
		}
	}
	fmt.Printf("%d dummy packets have been sent to encoder.\n\n", numPackets)
}

func handleMessageSend(message []byte, mode int) {
     	//fmt.Println(string(mode)+message)
	err = sendMessage(append([]byte{byte(mode)}, message))
	if err != nil {
		log.Fatal(err)
		return
	}
	
}

//sends given message to encoder.go at port 6000
func sendMessage(msg []byte) error {
	p :=  make([]byte, 2048)
	conn, err := net.Dial("udp", "127.0.0.1:6000")
	if err != nil {
		return err
	}
	//fmt.Fprintf(conn, msg)
	conn.Write(msg)
	_, err = bufio.NewReader(conn).Read(p)
	if err == nil {
		fmt.Printf("%s\n", p)
	} else {
		return err
	}
	conn.Close()
	return nil
}

func calcChecksum(csum uint32, data []byte) uint16 {
	var sum32 uint32 = sum16(data) + csum

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

//splits a 16 bit unsigned integer into two equally sized bytes
func split_uint16(num uint16) (byte, byte) {
	high := byte((num & (((1 << 8) - 1) << 8)) >> 8) //upper 8 bits
	low := byte(num & ((1 << 8) - 1)) //lower 8 bits
	return high, low
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
