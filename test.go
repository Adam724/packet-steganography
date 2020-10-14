package main

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	//"github.com/google/gopacket/pcapgo"
    "log"
    "strings"
    "time"
    //"errors"
)

var (
    device      string = "ens33"
    snapshotLen int32  = 1024
    promiscuous bool   = false
    err         error
    timeout     time.Duration = 30 * time.Second
    handle      *pcap.Handle
)

//Checksum computation for TCP/UDP
type tcpipchecksum struct {
     psuedoheader tcpipPsuedoHeader
}

type tcpipPsuedoHeader interface {
     psuedoheaderChecksum() (uint32, error)
}

func main() {
	
    // Open device
    handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
    if err != nil {log.Fatal(err) }
    defer handle.Close()

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
	    printPacketInfo(packet, handle)
    }
}

func printPacketInfo(packet gopacket.Packet, handle *pcap.Handle) {
    // Let's see if the packet is TCP
   /* tcpLayer := packet.Layer(layers.LayerTypeTCP)
    if tcpLayer != nil {
        fmt.Println("TCP layer detected.")
        tcp, _ := tcpLayer.(*layers.TCP)

        // TCP layer variables:
        // SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
        // Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
        fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
        fmt.Println("Sequence number: ", tcp.Seq)
	fmt.Println("Checksum: ", tcp.Checksum)
	networkLayer := packet.NetworkLayer()
	err = tcp.SetNetworkLayerForChecksum(networkLayer)
	if err != nil{
	   fmt.Println("SETTING NETWORK LAYER FOR CHECKSUM RESULTED IN ERROR: ", err)
	}else{
	   csum, error := tcp.ComputeChecksum()
	   if err != nil{
	      fmt.Println("CALCULATING CHECKSUM RESULTED IN AN ERROR: ", error)
	   }else{
	      fmt.Println("Calculated checksum: ", csum)
	   }
	}
        fmt.Println()
    }*/


    //check if packet is UDP
    udpLayer := packet.Layer(layers.LayerTypeUDP)
    if udpLayer != nil {
	    fmt.Println("UDP layer detected.") 
	    udp, _ := udpLayer.(*layers.UDP)
	    
	    fmt.Printf("From port %d to %d\n", udp.SrcPort, udp.DstPort)
	    fmt.Println("Checksum: ", udp.Checksum)
	    networkLayer := packet.NetworkLayer()
	    err = udp.SetNetworkLayerForChecksum(networkLayer)
	    if err != nil {
		    fmt.Println("SETTING NETWORK LAYER FOR CHECKSUM RESULTED IN ERROR: ", err)
	    }else{
		
		buffer := gopacket.NewSerializeBuffer()
		options := gopacket.SerializeOptions{
			ComputeChecksums: false,
			FixLengths:       true,
		}	
		
		err := udp.SerializeTo(buffer, options)
		if err != nil {
			fmt.Println("ERROR SERIALIZING UDP PACKET: ", err)
		}else {
			udp.Checksum = 0
			//headerAndPayload := udp.BaseLayer.Contents
			headerAndPayload := append(buffer.Bytes(), udp.BaseLayer.Payload...)
			headerAndPayload[6] = 0
			headerAndPayload[7] = 0
			ip := networkLayer.(*layers.IPv4)
			headerProtocol := ip.Protocol
			csum, err := udpChecksum(headerAndPayload, headerProtocol, ip)
			if err != nil {
				fmt.Println("Error computing checksum: ", err)
			}else {
				fmt.Println("Calculated checksum: ", csum)
				fmt.Println("networkLayer.LayerContents(): ", networkLayer.LayerContents())
				//fmt.Println("udp.LayerContents(): ", udp.LayerContents())
				//fmt.Println("headerAndPayload: ", headerAndPayload)
				//fmt.Println("udp.Payload(): ", udp.BaseLayer.Payload)
				//fmt.Printf("srcIP: %d destIP: %d\n", ip.SrcIP, ip.DstIP)
				//fmt.Println("udp.Length: ", udp.Length )
				//fmt.Println("ip.Protocol: ", uint8(headerProtocol))
				fmt.Println(packet.Data())

				//append a message to the raw packet data and send it
				rawBytes := packet.Data()
				rawBytes = append(rawBytes, "test message"...)
				err = handle.WritePacketData(rawBytes)
				if err != nil {
					log.Fatal(err)
				}
			}	
			
		}
	    }
		
	    fmt.Println()
	
    }

    // Iterate over all layers, printing out each layer type
    fmt.Println("All packet layers:")
    for _, layer := range packet.Layers() {
        fmt.Println("- ", layer.LayerType())
    }

    // When iterating through packet.Layers() above,
    // if it lists Payload layer then that is the same as
    // this applicationLayer. applicationLayer contains the payload
    applicationLayer := packet.ApplicationLayer()
    if applicationLayer != nil {
        fmt.Println("Application layer/Payload found.")
        fmt.Printf("%s\n", applicationLayer.Payload())

        // Search for a string inside the payload
        if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
            fmt.Println("HTTP found!")
        }
    }

    // Check for errors
    if err := packet.ErrorLayer(); err != nil {
        fmt.Println("Error decoding some part of the packet:", err)
    }
}


func psuedoheaderChecksum4(ip *layers.IPv4) (csum uint32, err error) {
     if err := ip.AddressTo4(); err != nil {
     	return 0, err
     }
     csum += (uint32(ip.SrcIP[0]) + uint32(ip.SrcIP[2])) << 8;
     csum += uint32(ip.SrcIP[1]) + uint32(ip.SrcIP[3]);
     csum += (uint32(ip.DstIP[0]) + uint32(ip.DstIP[2])) << 8;
     csum += uint32(ip.DstIP[1]) + uint32(ip.DstIP[3]);
     return csum, nil;
}

func psuedoheaderChecksum6(ip *layers.IPv6) (csum uint32, err error) {
     if err := ip.AddressTo16(); err != nil {
     	return 0, err
     }
     for i := 0; i< 16; i += 2 {
     	 csum += uint32(ip.SrcIP[i]) << 8
	 csum += uint32(ip.SrcIP[i+1])
	 csum += uint32(ip.DstIP[i]) << 8
	 csum += uint32(ip.DstIP[i+1])
     }
     return csum, nil
}

//Calculate the TCP/IP checksum, including any previously calculated
//checksum data
func tcpipChecksum(data []byte, csum uint32) uint16 {
     length := len(data) - 1
     for i := 0; i < length; i += 2 {
     	 csum += uint32(data[i]) << 8
	 csum += uint32(data[i+1])

     }
     if len(data) % 2 == 1 {
     	csum += uint32(data[length])
     }
     for csum > 0xffff {
     	 csum = (csum >> 16) + (csum & 0xffff)
     }
     return ^uint16(csum)
}

func udpChecksum(headerAndPayload []byte, headerProtocol layers.IPProtocol, ip *layers.IPv4) (uint16, error) {
	length := uint32(len(headerAndPayload))
	csum, err := psuedoheaderChecksum4(ip)
	if err != nil {
		return 0, err
	}
     csum += uint32(headerProtocol)
     csum += length & 0xffff
     csum += length >> 16
     return tcpipChecksum(headerAndPayload, csum), nil
}

/*func calcChecksum(phdr []byte, packet []byte) uint16 {
	var sum32 uint32 = sum16(packet) + sum16(phdr)

	//convert uint32 to uint16 by repeatedly adding carries
	for i := 0; sum32 > 131071; i++{
		sum32 = ((sum32 & (((1 << 16) - 1) << 16) ) >> 16) + (sum32 & ((1 << 16) - 1))
	}
	fmt.Printf("%x\n", sum32)
	fmt.Printf("%d", ^uint16(sum32))
	return ^uint16(sum32)
}

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
}*/
