package main

import (
	"fmt"
	"log"
	"net"
)



func main()  {
	tcp_address := net.IPAddr{
		IP: net.IPv4(127,0,0,1),
	}

	log.Println("Listening on TCP connection")
	listener, err := net.ListenIP("ip4:1", &tcp_address)

	if err != nil {
		log.Fatal("An error occured while listening for tcp connections.", err)
	}

	log.Println("IP address is ", tcp_address)

	for {
		buffer := make([]byte, 1024)

		numBytes, _, err := listener.ReadFrom(buffer)

		if err != nil {
			log.Fatal("An error occured while reading data into buffer", err)
		}

		log.Println("The number of bytes read are ", numBytes)

		fmt.Printf("% X\n", buffer[:numBytes])
	}
}