package packets

import (
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	localDeviceName = "lo0"
)

var InetAddr string

type DNS_DATA struct {
	DNS_NAME string
	DST_IP string
	SRC_IP string
}

var dns layers.DNS

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
		for _, address := range dev.Addresses {
			if dev.Name == device {
				InetAddr = address.IP.String()
			}
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}

		if dev.Name == device {
			return true
		}
	}
	return false
}

func getPacketData(packet gopacket.Packet) gopacket.Packet {
	app := packet.ApplicationLayer()
	if app != nil {
		return packet
	}
	return nil
}

func GetDNSPackets(deviceName string, dnsChan chan DNS_DATA) {
	deviceExists := checkForDevice(deviceName)
	if deviceExists == false {
		log.Fatal("Device not found, the interface to listen on wasnt found", deviceName)
	}

	filter := "udp and port 53 and src host 192.168.0.125" 

	handler, err := startPacketSniffer(deviceName, filter)
	if err != nil {
		log.Fatal("Error")
	}
	defer handler.Close()

	if err != nil {
		log.Panic(err)
	}
	var SrcIP string
	var DstIP string

	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var dns layers.DNS
	var payload gopacket.Payload

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &dns, &payload)
	decodedLayers := make([]gopacket.LayerType, 0, 10)

	for {
		data, _, err := handler.ReadPacketData()
		if err != nil {
			log.Panic("Error reading packet layer --> ", err)
		}

		log.Println("Data from read packet data", data)

		parser.DecodeLayers(data, &decodedLayers)

		for _, typ := range decodedLayers {
			switch typ {
			case layers.LayerTypeIPv4:
				SrcIP = ip4.SrcIP.String()
				DstIP = ip4.DstIP.String()
				// dnsChan <- DNS_DATA{
				// 	DST_IP: DstIP,
				// 	SRC_IP: SrcIP,
				// }
				pushDNSDataToChannel(DNS_DATA{
					DST_IP: DstIP,
					SRC_IP: SrcIP,
				}, dnsChan)
			case layers.LayerTypeIPv6:
				SrcIP = ip6.SrcIP.String()
				DstIP = ip6.DstIP.String()
				pushDNSDataToChannel(DNS_DATA{
					DST_IP: DstIP,
					SRC_IP: SrcIP,
				}, dnsChan)
			case layers.LayerTypeDNS:
				// dnsOpCode := int(dns.OpCode)
				dnsResponseCode := int(dns.ResponseCode)
				dnsANCount := int(dns.ANCount)

				if (dnsANCount == 0 && dnsResponseCode > 0) || (dnsANCount > 0) {
					var data DNS_DATA
					for _, dnsQuestion := range dns.Questions {
						data.DNS_NAME = string(dnsQuestion.Name)
						data.DST_IP = DstIP
						data.SRC_IP = SrcIP

						log.Println(data)
						dnsChan <- data
					}
				}
			}
		}
	}
}

func pushDNSDataToChannel(data DNS_DATA, channel chan DNS_DATA) {
	channel <- data
}

func startPacketSniffer(deviceName string, filter string) (*pcap.Handle, error) {
	handler, err := pcap.OpenLive(deviceName, 1600, false, pcap.BlockForever)
	if err != nil {
		return nil, errors.New("Error occured when trying to listen on device " + deviceName)
	}

	if err := handler.SetBPFFilter(filter); err != nil {
		return nil, errors.New(fmt.Sprint("Error occured filtering tcp and udp packets ", err))
	}

	return handler, nil
}

func StartPacketSniffing(deviceName string, channel chan gopacket.Packet) {
	// deviceName := setDeviceNameFromOperatingSystem()
	filter := "tcp"
	deviceExists := checkForDevice(deviceName)
	if deviceExists == false {
		log.Fatal("Device not found, the interface to listen on wasnt found", deviceName)
	}

	handler, err := startPacketSniffer(deviceName, filter)
	if err != nil {
		log.Fatal("Error")
	}
	defer handler.Close()

	source := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range source.Packets() {
		channel <- getPacketData(packet)
	}
}
