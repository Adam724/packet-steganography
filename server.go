package main

import (
        "fmt"
        "math/rand"
        "net"
        "os"
        "strings"
        "time"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func random(min, max int) int {
        return rand.Intn(max-min) + min
}

func main() {
        arguments := os.Args
        if len(arguments) == 1 {
                fmt.Println("Please provide a port number!")
                return
        }
        PORT := ":" + arguments[1]

        s, err := net.ResolveUDPAddr("udp4", PORT)
        if err != nil {
                fmt.Println(err)
                return
        }

        connection, err := net.ListenUDP("udp4", s)
        if err != nil {
                fmt.Println(err)
                return
        }

        defer connection.Close()
        buffer := make([]byte, 1024)
        rand.Seed(time.Now().Unix())

        for {
                n, addr, err := connection.ReadFromUDP(buffer)
		if err != nil{
		   fmt.Print("Error reading from buffer")
		   return
		}
                fmt.Print("-> ", string(buffer[0:n-1]))

		packet_data := []byte(string(buffer[0:n-1]))
		packet := gopacket.NewPacket(packet_data, layers.LayerTypeUDP, gopacket.Default)
		//check if packet is UDP
    		udpLayer := packet.Layer(layers.LayerTypeUDP)
    		if udpLayer != nil {
	    	   	udp, _ := udpLayer.(*layers.UDP)
			//This is nil for some reason
			networkLayer := packet.NetworkLayer()
		
				buffer := gopacket.NewSerializeBuffer()
				options := gopacket.SerializeOptions{
					ComputeChecksums: false,
					FixLengths:       true,
				}	
		
				err := udp.SerializeTo(buffer, options)
				if err != nil {
				        fmt.Println("error udp.SerializeTo()")
					return
				}else{
					udp.Checksum = 0
					//headerAndPayload := udp.BaseLayer.Contents
					headerAndPayload := append(buffer.Bytes(), udp.BaseLayer.Payload...)
					headerAndPayload[6] = 0
					headerAndPayload[7] = 0
					ip := networkLayer.(*layers.IPv4)
					headerProtocol := ip.Protocol
				
					csum, error := udpChecksum(headerAndPayload, headerProtocol, ip)
					if error != nil{
					   	fmt.Println("err udpChecksum()")
						return
					}else{
						fmt.Println("Sent checksum: ", udp.Checksum)
						fmt.Println("Calculated checksum: ", csum)
					
						if abs(int64(udp.Checksum - csum)) > 1000{
					   	   fmt.Println("Checksum is wrong. Will notify client.")
					   
						   data := []byte("Checksums do not match.")
                			   	   fmt.Printf("data: %s\n", string(data))
                			     	   _, err = connection.WriteToUDP(data, addr)
					   
						   if err != nil {
                        		      	      fmt.Println(err)
                        		      	      return
					   	   }
					   
						}else{
						   fmt.Println("Checksums match. Will notify client.")

					   	   data := []byte("Checksums match, nice.")
                			   	   fmt.Printf("data: %s\n", string(data))
                			   	   _, err = connection.WriteToUDP(data, addr)
					   
						   if err != nil {
                        		      	      fmt.Println(err)
                        		      	      return
					   	   }
			                	}
					}
				
			}
			
	    	}else{
			fmt.Println("Packet is allegedly not UDP.")
			 data := []byte("Packet is somehow not UDP.")
                	 fmt.Printf("data: %s\n", string(data))
			 _, err = connection.WriteToUDP(data, addr)
					   
			 if err != nil {
                            fmt.Println(err)
                       	    return
			 }
		}
		

                if strings.TrimSpace(string(buffer[0:n])) == "STOP" {
                        fmt.Println("Exiting UDP server!")
                        return
                }

                
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



func abs(x int64) int64 {
     if x < 0 {
     	  return -x
     }
     return x
}