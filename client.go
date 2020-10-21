package main

import (
        "bufio"
        "fmt"
        "net"
        "os"
        "strings"
	"strconv"
)

func main() {
        arguments := os.Args
        if len(arguments) == 1 {
                fmt.Println("Please provide a host:port string")
                return
        }
        CONNECT := arguments[1]

        s, err := net.ResolveUDPAddr("udp4", CONNECT)
        c, err := net.DialUDP("udp4", nil, s)
        if err != nil {
                fmt.Println(err)
                return
        }

        fmt.Printf("The UDP server is %s\n", c.RemoteAddr().String())
        defer c.Close()

	



        for {
                reader := bufio.NewReader(os.Stdin)
                fmt.Print(">> ")
                text, _ := reader.ReadString('\n')
		
		// Payload: 'test message' in ASCII
		payload := []byte(text + "\n")
		
                
		

		//set srcMAC and dstMAC in ethernet header. Will be the same if sending to same device
	
		//srcMAC := getMacAddr()
		//ethHeader := []byte{0}
		//ethHeader = append(ethHeader, srcMAC)
		//ethHeader = append(ethHeader, srcMac)
        
	
		//version: 4, header length(in 4 byte words): 5, TOS: 0, Length: ?, identifier: ?, flags: 4,
		//offset: 0, TTL: 64, protocol: 17 (udp), checksum: ?, srcIP: 127.0.0.1, dstIP: 127.0.0.1
		ipHeader := []byte{45, 0, 0, 0, 33, 151, 4, 0, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1}

		//srcPort: 3000, dstPort: 8080, length: ?, checksum: ?
		udpHeader := []byte{11, 184, 31, 144, 0, 0, 0, 0}

		//construct raw packet from headers and payload and calculate length in bytes
		packet := append(append(ipHeader, udpHeader...), payload...)
		var length uint16 = uint16(len(packet))
		high, low := split_uint16(length)

		//set length field in udp and ip headers
		udpHeader[4] = high
		udpHeader[5] = low
		ipHeader[3] = high
		ipHeader[4] = low

		//pseudoHeader for udp checksum. srcIP, dstIP, protocol, length
		pseudoHeader := append(ipHeader[len(ipHeader) - 9:], 17)
		pseudoHeader = append(pseudoHeader, ipHeader[3:5]...)

		//calculate and set udp checksum
		data := append(udpHeader, payload...)
		checksum := udpChecksum(pseudoHeader, data)
		high, low = split_uint16(checksum)

		udpHeader[6] = high
		udpHeader[7] = low

		//calculate and set ip header checksum
		checksum = ipChecksum(ipHeader)
		high, low = split_uint16(checksum)

		ipHeader[12] = high
		ipHeader[13] = low

		//all header fields have been calculated/populated, so reconstruct packet
		packet = append(append(ipHeader, udpHeader...), payload...)
		fmt.Println(packet)

		_, err = c.Write(packet)
                if strings.TrimSpace(string(payload)) == "STOP" {
                        fmt.Println("Exiting UDP client!")
                        return
                }

		if err != nil {
                        fmt.Println(err)
                        return
                }
                

                buffer := make([]byte, 1024)
                n, _, err := c.ReadFromUDP(buffer)
                if err != nil {
                        fmt.Println(err)
                        return
                }
                fmt.Printf("Reply: %s\n", string(buffer[0:n]))
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

//splits a 16 bit unsigned integer into two equally sized bytes
func split_uint16(num uint16) (byte, byte) {
	high := byte((num & (((1 << 8) - 1) << 8)) >> 8) //upper 8 bits
	low := byte(num & ((1 << 8) - 1)) //lower 8 bits
	return high, low
}

//gets the MAC address of this machine as byte array
func getMacAddr() ([]byte, error) {
    ifas, err := net.Interfaces()
    if err != nil {
        return nil, err
    }
    var macBytes []byte
    for _, ifa := range ifas {
        a := ifa.HardwareAddr.String()
        if a != "" {
		strBytes := strings.Split(a, ":")
		for i := 0; i < len(strBytes); i++ {
			b, _ := strconv.ParseInt(strBytes[i], 16, 8)
			result := byte(b)
			macBytes = append(macBytes, result)
		}
		
        }
    }
    return macBytes, nil
}

/*
package main

import (
	
	"fmt"
	"log"
	"net"
	"time"
	"strings"
	"strconv"
)

var (
    device       string = "ens33"
    snapshot_len int32  = 1024
    promiscuous  bool   = false
    err          error
    timeout      time.Duration = 30 * time.Second
    handle       *pcap.Handle
)


func main() {
     	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {log.Fatal(err) }
	defer handle.Close()
	
	err = handle.WritePacketData(packet)
	if err != nil {
		log.Fatal(err)
	}
}


*/