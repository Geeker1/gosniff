package main

import (
	"fmt"
	"log"
	"os"
	"syscall"
)

func main()  {

	for {
		log.Println("Listening for socket information.")
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)

		if err != nil{
			log.Fatalln("Error while creating socket", err)
		}

		log.Println("Socket has been created, listening in to fetch IP packets.")

		file := os.NewFile(uintptr(fd), fmt.Sprintf("gosniff %d", fd))

		for {
			buffer := make([]byte, 1024)

			numBytes, err := file.Read(buffer)

			if err != nil {
				log.Fatal("An error occured while reading data into buffer", err)
			}

			log.Println("The number of bytes read are ", numBytes)

			fmt.Printf("% X\n", buffer[:numBytes])
		}
	}
}