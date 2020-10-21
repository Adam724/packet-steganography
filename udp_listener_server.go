package main

import (
        "fmt"
        "math/rand"
        "net"
        "os"
        "strings"
        "time"
)

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
                fmt.Print("-> ", buffer[:n])

                if strings.TrimSpace(string(buffer[0:n])) == "STOP" {
                        fmt.Println("Exiting UDP server!")
                        return
                }

                data := []byte("Sup yo")
                fmt.Printf("data: %d\n", data)
                _, err = connection.WriteToUDP(data, addr)
                if err != nil {
                        fmt.Println(err)
                        return
                }
        }
}