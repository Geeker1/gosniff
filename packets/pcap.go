package packets

import (
	"log"
	"os"
	"runtime"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type PcapMethods interface {
	FindAllDevs() ([]pcap.Interface, error)
	OpenLiveConnection(deviceName string) (*pcap.Handle, error)
	createPacketSource(handler *pcap.Handle) *gopacket.PacketSource
	getPacketData(packet gopacket.Packet) PacketsData
	startSniffing(handler *pcap.Handle, p PcapMethods, message *SniffMessage)
}

type SniffMessage struct {
	Message chan PacketsData
}
type PacketsData struct {
	Dst string
	Src string
}

type PcapHandler struct{}

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

func (pH *PcapHandler) FindAllDevs() ([]pcap.Interface, error) {
	return pcap.FindAllDevs()
}

func (pH *PcapHandler) OpenLiveConnection(deviceName string) (*pcap.Handle, error) {
	handler, err := pcap.OpenLive(deviceName, 1600, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	return handler, nil
}

func checkForDevice(p PcapMethods, device string) bool {
	devs, err := p.FindAllDevs()
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

func StartPacketSniffing(p PcapMethods, deviceName string, message *SniffMessage) {
	// deviceName := setDeviceNameFromOperatingSystem()
	deviceExists := checkForDevice(p, deviceName)
	if deviceExists == false {
		log.Fatal("Device not found, the interface to listen on wasnt found", deviceName)
	}

	handler, err := p.OpenLiveConnection(deviceName)
	if err != nil {
		println(err)
		log.Panic("Error occured when trying to listen on device ", deviceName)
	}
	defer handler.Close()

	p.startSniffing(handler, p, message)
}

func (pH *PcapHandler) startSniffing(handler *pcap.Handle, p PcapMethods, message *SniffMessage) {
	if err := handler.SetBPFFilter(filter); err != nil {
		log.Panic("Error occured filtering tcp and udp packets ", err)
	}

	source := p.createPacketSource(handler)
	for packet := range source.Packets() {
		message.Message <- p.getPacketData(packet)
	}
}

func (pH *PcapHandler) getPacketData(packet gopacket.Packet) PacketsData {
	app := packet.ApplicationLayer()
	if app != nil {
		return PacketsData{
			Dst: packet.NetworkLayer().NetworkFlow().Dst().String(),
			Src: packet.NetworkLayer().NetworkFlow().Src().String(),
		}
	}

	return PacketsData{}
}

func (pH *PcapHandler) createPacketSource(handler *pcap.Handle) *gopacket.PacketSource {
	return gopacket.NewPacketSource(handler, handler.LinkType())
}
