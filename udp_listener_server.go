package main;
import ("fmt");
import ("net");

//Required for argo2verilog compiler
//;
func main() {
    p := make([]byte, 2048);
    addr := net.UDPAddr{
        Port: 3003,
        IP: net.ParseIP("127.0.0.1"),
    };
    ser, err := net.ListenUDP("udp", &addr);
    if err != nil {
        fmt.Printf("Some error %v\n", err);
        return;
    };
    fmt.Println("Listening...");
    for {
        _,remoteaddr,err := ser.ReadFromUDP(p);
        fmt.Printf("Read a message from %v %s \n", remoteaddr, p);
        if err !=  nil {
            fmt.Printf("Some error  %v", err);
            continue;
        };
    };
};
