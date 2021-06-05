package main

import (
	"flag"
	"fmt"
	"log"
	"net"
)

func constructIP(ap int, bp int, cp int, dp int) (a byte, b byte, c byte, d byte) {
	return byte(ap), byte(bp), byte(cp), byte(dp)
}

func main() {
	address := flag.String("address", "", "Defines the Address to listen on")
	flag.Parse()
	log.Println("Address value is", *address)

	/*
	* uses 127.0.0.1 when address is localhost
	* if not uses nil which listens on all ports
	*/
	tcp_address := &net.IPAddr{}
	if *address == "localhost" {
		tcp_address = &net.IPAddr{
			IP: net.IPv4(constructIP(127, 0, 0, 1)),
		}
	} else if *address == "" {
		tcp_address = nil
	}

	log.Println("Listening on TCP connection")
	listener, err := net.ListenIP("ip4:1", tcp_address)

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
