package main

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
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
        printPacketInfo(packet)
    }
}

func printPacketInfo(packet gopacket.Packet) {
    // Let's see if the packet is TCP
    tcpLayer := packet.Layer(layers.LayerTypeTCP)
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
/*
func (ip *IPv4) psuedoheaderChecksum() (csum uint32, err error) {
     if err := ip.AddressTo4(); err != nil {
     	return 0, err
     }
     csum += (uint32(ip.SrcIP[0]) + uint32(ip.srcIP[2])) << 8;
     csum += uint32(ip.SrcIP[1]) + uint32(ip.SrcIP[3]);
     csum += (uint32(ip.DstIP[0]) + uint32(ip.DstIP[2])) << 8;
     csum += uint32(ip.DstIP[1]) + uint32(ip.DstIP[3]);
     return csum, nil;
}

func (ip *IPv6) psuedoheaderChecksum() (csum uint32, err error) {
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

func (c * tcpipchecksum) computeChecksum(headerAndPayload []byte, headerProtocol IPProtocol) (uint16, error) {
     if c.psuedoheader == nil {
     	return 0, errors.New("TCP/IP layter 4 checksum cannot be computed without network layer... call SetNetworkLayerForChecksum to set which layer to use")
     }
     length := uint32(len(headerAndPayload))
     csum, err := c.psuedoheader.psuedoheaderChecksum()
     if err != nil {
     	return 0, err
     }
     csum += uint32(headerProtocol)
     csum += length & 0xffff
     csum += length >> 16
     return tcpipChecksum(headerAndPayload, csum), nil
}

func (i *tcpipchecksum) SetNetworkLayerForChecksum(l gopacket.NetworkLayer) error {
     switch v := l.(type){
     case *IPv4:
     	  i.psuedoheader = v
     case *IPv6:
          i.psuedoheader = v
     default:
	  return fmt.Errorf("cannot use layer type %v for tcp checksum network layer", l.LayerType())
     }
     return nil
}*/