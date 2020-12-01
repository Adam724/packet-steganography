# Raw Packet Steganography

### Motivation
Embed weakly encrypted messages in raw packet payloads.

### Running the Project
*You must have sudo privledges on your device in order to run these files*
```sh
npx create-react-app my-app
cd my-app
npm start
```

### Project Overview
**Client.go:** Sends a message and dummy udp packets to encoder.go. Capable of sending a string or a jpg file to be embedded. Client.go takes two command line arguments. The first is a flag, either -i or -m. If client.go is run with -i, the second command line argument must be a filepath to a jpg image. If -m is specified, the second command line argument must be a string.

**Encoder.go:** Receives a message and dummy packets from client.go. Encoder generates a small header that contains the destination ip address/port for the message, the total size of the message, and the sequence number of the current fragment being sent. Encoder then embeds the fragments of the message within the dummy udp packets by placing individual bits in random positions within the payload. Encoder then sends the dummy packet with the injected message fragment to decoder.go

**Decoder.go:** Listens for packets from encoder.go. When a packet is received, decoder separates the dummy packet from the message fragment that was embedded within it. Decoder adds the message fragment to a buffer, ordered by the fragment's sequence number, and forwards the original dummy packet to that packet's destination, found within the udp header.

### Next Steps
**NAT Table:** It would make the project a lot more robust if one were to design a NAT table that routes udp packets to encoder.go. This way, encoder.go would have naturally generated packets to embed the hidden message in, rather than dummy packets that have identical payloads.

**Encryption:** Currently, this project implements weak encryption. It embeds the messages in the payloads by using a random number generator with a specific seed to find random positions in the payload to place the bits of a message fragment. One way to improve the encryption process would be to encrypt the message fragment before placing it into the packet payload. Another way to improve upon encryption would be to add random arbitrary bits to the udp payload, and having decoder.go filter these random bits out. This would make it more difficult for attackers to determine what bits are part of the hidden message vs. the orignal payload.
