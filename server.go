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
	    fmt.Println(csum)
	    

	    // Here we will validate the checksum

	    
	    //pseudoHeader for udp checksum. srcIP, dstIP, protocol, length
	    psuedoHeader := []byte{}
	    psuedoHeader = append(psuedoHeader, ipHeader[12:]...) // This line is somehow breaking udpHeader
	    psuedoHeader = append(psuedoHeader, 17)
	    psuedoHeader = append(psuedoHeader, ipHeader[3:5]...)
	    

	    //calculate and set udp checksum
	    data := append(udpHeader[:6], payload...)
	    checksum := udpChecksum(psuedoHeader, data)

	    
	    fmt.Println(checksum)
	    
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
