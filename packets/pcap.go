package packets

import (
	"log"
	"os"
	"runtime"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	localDeviceName = "lo0"
	filter          = "tcp"
)

func setDeviceNameFromOperatingSystem() string {
	var deviceName string

	switch runtime.GOOS {
	case "linux":
		deviceName = "eth0"
	case "windows":
		deviceName = "\\Device\\NPF_{9CA25EBF-B3D8-4FD0-90A6-070A16A7F2B4}"
	case "darwin":
		deviceName = "en0"
	default:
		log.Fatal("Invalid operating system")
		os.Exit(1)
	}

	return deviceName
}

func FindAllDevices() ([]pcap.Interface, error) {
	return pcap.FindAllDevs()
}

func checkForDevice(device string) bool {
	devs, err := FindAllDevices()
	if err != nil {
		log.Fatal("Error occured while fetching devices")
	}

	for _, dev := range devs {
		if dev.Name == device {
			return true
		}
	}
	return false
}

func getPacketData(packet gopacket.Packet) gopacket.Packet {
	app := packet.ApplicationLayer()
	if app != nil {
		// payload := app.Payload()
		packet.NetworkLayer().NetworkFlow().Dst().Raw()
		// src := packet.NetworkLayer().NetworkFlow().Src()
		// // appPayload := packet.ApplicationLayer().Payload()
		// fmt.Print("Destination : ->", dst)
		// fmt.Print("Source: -> ", src)
		// // fmt.Print(string(appPayload))
		return packet
	}
	return nil
}

func StartPacketSniffing(deviceName string, channel chan gopacket.Packet) {
	// deviceName := setDeviceNameFromOperatingSystem()
	deviceExists := checkForDevice(deviceName)
	if deviceExists == false {
		log.Fatal("Device not found, the interface to listen on wasnt found", deviceName)
	}

	handler, err := pcap.OpenLive(deviceName, 1600, false, pcap.BlockForever)
	if err != nil {
		log.Panic("Error occured when trying to listen on device ", deviceName)
		log.Panic(err)
	}
	defer handler.Close()

	if err := handler.SetBPFFilter(filter); err != nil {
		log.Panic("Error occured filtering tcp and udp packets ", err)
	}

	source := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range source.Packets() {
		log.Println(packet)
		channel <- getPacketData(packet)
	}
}
