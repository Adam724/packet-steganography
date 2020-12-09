# Raw Packet Steganography

## Motivation
We wanted to develop a way to send ASCII messages and .jpeg files within raw packet payloads. Embedding messages in raw packet payloads would act as a method of secretive communication between two hosts. To make the messages harder to decypher, we wanted to implement a form of encryption so that attackers or firewalls would have a harder time piecing the original message together.

## Running the Project
*You must have have go installed and have sudo privledges on your device in order to run these files.*
```sh
sudo go run client.go <flag> <message>
```
Sends a message and dummy udp packets to encoder.go. Capable of sending a string or a jpg file to be embedded. Client.go takes two command line arguments. The first is a flag, either -i or -m. If client.go is run with -i, the second command line argument must be a filepath to a jpg image. If -m is specified, the second command line argument must be a string.

```sh
go run encoder.go
```
Receives a message and dummy packets from client.go. Encoder generates a small header that contains the destination ip address/port for the message, the total size of the message, and the sequence number of the current fragment being sent. Encoder then embeds the fragments of the message within the dummy udp packets by placing individual bits in random positions within the payload. Encoder then sends the dummy packet with the injected message fragment to decoder.go

```sh
go run decoder.go
```
Listens for packets from encoder.go. When a packet is received, decoder separates the dummy packet from the message fragment that was embedded within it. Decoder adds the message fragment to a buffer, ordered by the fragment's sequence number, and forwards the original dummy packet to that packet's destination, found within the udp header.

```sh
go run udp_listener_server.go
```
Listens for packets from decoder.go. This is where the original dummy packets are routed to once the message fragments are extracted within the decoder.

## Project Architecture
![Project Architecture](https://github.com/Adam724/packet-steganography/blob/master/architecture.png?raw=true)
Our steganography tool begins by accepting a user inputted message into client.go. This could either be a plaintext message or the path to a .jpg image file, specified by the -m and -i flags respectively. Client.go then constructs a raw udp packet from scratch using the gopacket library, sets the destination ip/port to that of our sample udp server, and calculates both the udp and ip checksum. Based on the length of the inputted data (considered as a byte array) and a max capacity value (a higher value means more of the message will be hidden in each packet), the number of packets that need to be sent to encoder.go in order to fully hide the message is calculated. When calculating how much of the message can fit inside each packet, we set a minimum of 19 bytes per packet. This is 8 bytes of the actual message plus the custom header of 11 bytes that is appended to every message fragment. Client.go then sends the full message byte array to encoder.go on port 6000 and sends the calculated number of dummy packets to encoder.go on port 3000. 

Encoder.go waits to receive the full message, then extracts the payload from the first packet it received and hides a fragment of the message in the payload. The message hiding process inserts each bit of the given message fragment into a random position in the bit string representation of the packet payload, as determined by a pseudo-random number generator. A custom header consisting of the total message length, destination ip address, destination port, sequence number, and mode (text or image) is appended to each fragment prior to hiding it. These fields are necessary for extraction in decoder.go and then to send the packet to its original destination. Finally, new udp and ip checksums are calculated, and the augmented packet is sent to decoder.go at port 3001. This process is repeated until the entire message has been hidden and all packets have been sent out. 

For each packet that decoder.go receives from encoder.go, the hidden message fragment is extracted from the payload and added to a buffer based on the sequence number in our custom header. The extraction process is the reverse of the message hiding process described above. Bits are extracted from the payload one at a time from the positions indicated by a pseudo-random number generator seeded with the same value as in encoder.go. Once the message buffer has reached the total message length specified in our header, we know the full message has been received. At this point, either the plaintext message is displayed, or a .jpg image is constructed from the message contents and saved to a file on the user’s machine. Whether the message is text or image data is specified by the mode value in our custom header. Lastly, the original payloads with message fragments extracted are sent to their original destination, also specified by the ip address and port number in our custom header.


