package main;

import ("fmt");
import ("github.com/google/gopacket");
import ("github.com/google/gopacket/pcap");
import ("log");
import ("time");
import ("net");
import ("math/rand");
import ("sort");
import ("errors");
import ("strconv");
import ("math");
import ("bytes");
import ("image/jpeg");
import ("bufio");
import ("os");

var (
    device       string = "lo";
    snapshot_len int32  = 1024;
    promiscuous  bool   = false;
    err          error;
    timeout      time.Duration = -1 * time.Second;
    handle       *pcap.Handle;
);

func main() {
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout);
	if err != nil {
		log.Fatal(err);
	};
	defer handle.Close();

	// Set filter to only listen for packets from port 3001 (encoder.go)
	var filter string = "udp and port 3001";
	err = handle.SetBPFFilter(filter);
	if err != nil {
		log.Fatal(err);
	};
	fmt.Println("Only capturing UDP port 3001 packets.");

	var totalLength uint16;
	var currLength uint16 = 0;
	var destPort uint16;
	var destIP []byte;
	var sequenceNumber uint16;
	var extractedHeader []byte;
	var extractedMsg []byte;
	var mode int;

	//Buffer to store the individual messages that come in. Each piece of the secret
	//message will be indexed by its sequence number
	buffer := make([]byte, 0);
	
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType());
	for packet := range packetSource.Packets() {
		rawBytes := packet.Data();

		//Length of ipHeader in 4 byte words
		ipLen := rawBytes[14] & 0b1111;
		
		ipEndIndex := 14 + (4 * ipLen);
		udpEndIndex := ipEndIndex + 8;

		//get the packet payload
		payload := rawBytes[udpEndIndex:];

		//length of the message hidden in this packet
		mLen := uint16(payload[len(payload) - 1]);
		payload = payload[:len(payload) - 1];

		//extract the portion of message hidden in this payload (contains custom header)
		extractedFragment, originalPayload := extractMessage(payload, mLen, true);
		
		//get the fields from extracted custom header
		extractedHeader = extractedFragment[:11];
		extractedMsg = extractedFragment[11:];
		destPort  = (uint16(extractedHeader[0]) << 8) + uint16(extractedHeader[1]);
		destIP = extractedHeader[2:6];
		totalLength = (uint16(extractedHeader[6]) << 8) + uint16(extractedHeader[7]);
		sequenceNumber = (uint16(extractedHeader[8]) << 8) + uint16(extractedHeader[9]);
		mode = int(extractedHeader[10]);

		fmt.Printf("***Packet with sequence number %d was received***\n", sequenceNumber);
		fmt.Printf("Original destination port: %d\n", destPort);
		fmt.Println("Original destination ip: ", destIP);

		
		//Adding message segment to buffer
		buffer = append(buffer, extractedMsg);
		currLength += uint16(len(extractedMsg));
		fmt.Printf("We have read %d bytes and are waiting for %d more bytes.\n", currLength, (totalLength-currLength));
		fmt.Println("------------------------------------------\n");
		
		extractedHeader = make([]byte, 0);
		extractedMsg = make([]byte, 0);
		
		if currLength >= totalLength {
			fmt.Println("Full message received:");
			//interpret as text message
			if mode == 1 {
			   //Print message
			   fmt.Println(string(buffer));
			}else if mode == 2 { //interpret as jpeg image
			   //Store image
			   img, err := jpeg.Decode(bytes.NewReader(buffer));
			   if err != nil {
			      log.Fatalln(err);
			   };
			   out, _ := os.Create("./img.jpeg");
			   defer out.Close();

			   var opts jpeg.Options;
			   opts.Quality = 100 ;//1-100, 100 is best quality

			   err = jpeg.Encode(out, img, &opts);

			   if err != nil {
			      log.Println(err);
			   };
			   
			};
			
			fmt.Println("------------------------------------------\n\n");
			currLength = 0;
			buffer = make([]byte, 0);
		};


		//Send original payload to original destination port
		go sendMessage(string(originalPayload), destPort, int(sequenceNumber));
		
		
	};
};

//extract hidden message from payload
func extractMessage(data []byte, msgLen uint16, setSeed bool) (extractedMsg []byte, origData []byte) {
	dataBinStr := bytesToBin(data);
	numBits := int(msgLen) * 8;
	if setSeed {
		rand.Seed(1111) ;//MUST be same as in encoder.go
	};

	var randPositions = make([]int, numBits, numBits);

	//get postions where each bit of message is hidden
	for i := 0; i < numBits; i++ {
		randIndex := rand.Intn(len(dataBinStr) - numBits + i);
		randPositions[i] = randIndex;
	};
	sort.Ints(randPositions);

	//extract the bits and return resulting hidden message
	newStr := dataBinStr;
	msgBin := "";
	for i := numBits - 1; i >= 0; i-- {
		bit, altered := extractBit(newStr, randPositions[i]);
		newStr = altered;
		msgBin = bit + msgBin;
	};
	return binToBytes(msgBin), binToBytes(newStr);
};

//remove single bit from bit string at given index
func extractBit(data string, index int) (bit string, newStr string) {
	newStr = data[:index+1] + data[index + 2:];
	return data[index+1:index+2], newStr;
};

//convert readable ascii string to bit string
func bytesToBin(b []byte) (binString string) {
    for _, c := range b {
        binString = fmt.Sprintf("%s%.8b", binString, c);
    };
    return ;
};

//convert a bit string to readable ascii string
func binToBytes(s string) []byte {
	b := make([]byte, 0);
	for i := 0; i < len(s); i += 8 {
		n, _ := strconv.ParseUint(s[i:i+8], 2, 8);
		b = appendOne(b, byte(n));
	};
	return b;
};

func sendMessage(msg string, port uint16, sequenceNumber int) {
	p :=  make([]byte, 2048);
	conn, err := net.Dial("udp", "127.0.0.1:" + strconv.Itoa(int(port)));
	if err != nil {
		//return err
		fmt.Printf("!! Error sending packet with sequence number %d to original destination !!\n", sequenceNumber);
	};
	fmt.Fprintf(conn, msg);
	_, err = bufio.NewReader(conn).Read(p);
	if err == nil {
		fmt.Printf("%s\n", p);
	} else {
		//return err
		fmt.Printf("!! Error sending packet with sequence number %d to original destination !!\n", sequenceNumber);
	};
	conn.Close();
	//return nil
};

//combines 2 equally sized bytes to form a 16 bit integer
func combine_uint16(high byte, low byte) (uint16) {
        num := (uint16(high)*256) + uint16(low);
	return num;
};


//manual append function to combine two byte arrays for verilog compiler
func append(arr1 []byte, arr2 []byte) []byte {
	arr1Len := len(arr1);
	newLen := len(arr1) + len(arr2);
	result := make([]byte, newLen);
	
	for i:= 0; i < arr1Len; i++ {
		result[i] = arr1[i];
	};
	
	for i := 0; i < len(arr2); i++ {
		result[i + arr1Len] = arr2[i];
	};
	return result;
};

//appends single byte to byte array in verilog-compiler safe way
func appendOne(arr1 []byte, oneByte byte) []byte {
	result := make([]byte, len(arr1) + 1);
	for i:= 0; i < len(arr1); i++ {
		result[i] = arr1[i];
	};
	result[len(result) - 1] = oneByte;
	return result;
};
