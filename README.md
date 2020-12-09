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

## Project Description
![Project Architecture](https://github.com/Adam724/packet-steganography/blob/master/architecture.png?raw=true)

We wanted our project to contain an encoder and a decoder server. The encoder server would receive a secret message and dummy packets from a client. The encoder would then fragment the secret message and embed it within the payloads of the dummy packets by placing each bit of a message fragment in a random position, determined by a random number generator. We also designed a small header to attach to each message fragment that identifies the sequence number of that fragment as well as other relevant information. Once a message fragment is embedded in a dummy packet, the encoder adjusts the checksums and other fields in the dummy packet’s headers to ensure the augmented packet does not look tampered with. The augmented packet is then sent from the encoder to the decoder.

The decoder receives the dummy packets with message fragments embedded within them. The decoder has the same seed as the encoder, which is used to determine the positions that the message fragment’s bytes were placed within the dummy packet’s payload. After extracting each byte of the message fragment, the decoder will use the sequence number found in the message fragment’s header to place each fragment in its respective position in a buffer. The original dummy packet is then forwarded to its original destination. Upon receiving the full secret message, the decoder will combine the fragments and will either print the message or save it as a jpeg, depending on whether an ASCII message or a jpeg file was sent.

## Future Work/Enhancements: 
* **NAT Table:** It would make the project a lot more practical if one were to design a NAT table that routes udp packets to encoder.go. This way, encoder.go would have naturally generated packets to embed the hidden message in, rather than dummy packets that have identical payloads. Ultimately this would allow for the client to only send the message they hope to embed to the encoder, and the NAT table would route a stream of legitimate UDP packets to encoder to embed message fragments within.
* **Encryption:** Currently, this project implements a form of weak encryption. It embeds the messages in the payloads by using a random number generator with a specific seed to find random positions in the payload to place the bits of a message fragment. One way to improve the encryption process would be to encrypt the message fragment before placing it into the packet payload. Another way to improve upon encryption would be to add random arbitrary bits to the udp payload, and having decoder.go filter these random bits out. This would make it more difficult for attackers to determine what bits are part of the hidden message vs. the original payload.
* **Stream capability:** This project is currently capable of sending a single message between the encoder and decoder. Adding functionality to communicate datastreams between the encoder and decoder would add a massive amount of functionality to this project. Example datastreams could be Spotify music, live stock market updates, and live sporting events. One would have to build functionality on the decoder side to present the contents of the stream to the user. Essentially, designing an interface to display the live video feed or play the live music feed. One would also have to build functionality on the encoder that perpetually listens to a data stream and does not require a total message length to run. Also, one would have to ensure that the encoder could reroute the stream data faster than the encoder receives the stream in order to prevent a potential bottleneck.
* **Maximum message size:** Currently, the maximum message size one can communicate using our system is approximately 64,000 bytes. This is because client.go initially sends the message to encoder.go through a UDP packet, which has a maximum size of 65,507 bytes. If one were to increase this limit, it would allow for higher resolution pictures, larger bodies of text, and even videos to be communicated using this system. This could be done by fragmenting the message within client.go before sending it to the encoder.
* **More file types:** We currently only have functionality to communicate jpeg images between the encoder and decoder. A great way to add to this project would be to add functionality to send more file types. This can be done by using various libraries available to Go developers to read the raw bytes of files. For instance, we used the “images/jpeg” library to read jpeg files, but the images library also contains functionality to read other image file types.
