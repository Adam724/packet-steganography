# Raw Packet Steganography

## Motivation
We wanted to develop a way to send ASCII messages and .jpeg files within raw packet payloads. Embedding messages in raw packet payloads would act as a method of secretive communication between two hosts. To make the messages harder to decypher, we wanted to implement a form of encryption so that attackers or firewalls would have a harder time piecing the original message together.

## Running the Project
*You must have have go installed and have sudo privledges on your device in order to run these files.*
```sh
sudo go run client.go <flag> <message>
```
```sh
sudo go run encoder.go
```
```sh
sudo go run decoder.go
```
```sh
sudo go run udp_listener_server.go
```

## Project Overview
**Client.go:** Sends a message and dummy udp packets to encoder.go. Capable of sending a string or a jpg file to be embedded. Client.go takes two command line arguments. The first is a flag, either -i or -m. If client.go is run with -i, the second command line argument must be a filepath to a jpg image. If -m is specified, the second command line argument must be a string.

**Encoder.go:** Receives a message and dummy packets from client.go. Encoder generates a small header that contains the destination ip address/port for the message, the total size of the message, and the sequence number of the current fragment being sent. Encoder then embeds the fragments of the message within the dummy udp packets by placing individual bits in random positions within the payload. Encoder then sends the dummy packet with the injected message fragment to decoder.go

**Decoder.go:** Listens for packets from encoder.go. When a packet is received, decoder separates the dummy packet from the message fragment that was embedded within it. Decoder adds the message fragment to a buffer, ordered by the fragment's sequence number, and forwards the original dummy packet to that packet's destination, found within the udp header.

**Udp_listener_server.go:** Listens for packets from decoder.go. This is where the original dummy packets are routed to once the message fragments are extracted within the decoder.

![Project Architecture](https://github.com/Adam724/packet-steganography/blob/master/architecture.png?raw=true)

