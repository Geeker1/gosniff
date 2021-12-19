package decoder

import (
	"encoding/hex"
	"log"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func getIPLayer() *layers.IPv4 {
	return &layers.IPv4{
		SrcIP:      net.IP{127, 0, 0, 1},
		DstIP:      net.IP{8, 8, 8, 8},
		Version:    4,
		IHL:        5,
		TOS:        0,
		Id:         31873,
		Length:     40,
		Flags:      2,
		FragOffset: 0,
		TTL:        55,
		Checksum:   8239,
		Options:    nil,
		Padding:    nil,
	}
}

func getTCPLayer() *layers.TCP {
	return &layers.TCP{
		SrcPort:    layers.TCPPort(4321),
		DstPort:    layers.TCPPort(80),
		DataOffset: 5,
		Seq:        497,
		Ack:        1975,
		FIN:        false,
		SYN:        false,
		RST:        false, PSH: false, ACK: true, URG: false, ECE: false, CWR: false, NS: false,
		Window: 331,
		Urgent: 0,
	}
}

func getTLSLayer() *layers.TLS {
	cipherRecord := layers.TLSChangeCipherSpecRecord{
		Message: 1,
		TLSRecordHeader: layers.TLSRecordHeader{
			ContentType: 20,
			Version:     0x0303,
		},
	}

	return &layers.TLS{
		ChangeCipherSpec: []layers.TLSChangeCipherSpecRecord{
			cipherRecord,
		},
	}
}

func getUDPLayer() *layers.UDP {
	return &layers.UDP{
		SrcPort: layers.UDPPort(4000),
		DstPort: layers.UDPPort(80),
	}
}

func getEthernetLayer() *layers.Ethernet {
	return &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
		DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
		EthernetType: 2048,
	}
}

func getBaseLayers() (*layers.Ethernet, *layers.IPv4) {
	ipLayer := getIPLayer()
	ethernetLayer := getEthernetLayer()

	return ethernetLayer, ipLayer
}

func constructPacket(
	ethLayer *layers.Ethernet, ipLayer *layers.IPv4,
	transportPacket interface{},
) gopacket.Packet {
	rawBytes := []byte{10, 20, 30}

	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buffer, opts,
		ethLayer,
		ipLayer,
		transportPacket.(gopacket.SerializableLayer),
		gopacket.Payload(rawBytes),
	)
	outgoingPacket := buffer.Bytes()

	ethpacket := gopacket.NewPacket(outgoingPacket,
		layers.LayerTypeEthernet,
		gopacket.Default)

	return ethpacket
}

func constructTLSPacket() gopacket.Packet {
	const tlsHexDump = "b41c30c04592c4d987861a0f080045000068e5f340004006ba19c0a8008e6812713ac03401bb3cc11691112fcc5d501801f5599d000014030300010117030300351ffacbf291a466c16a56ef949cebace34c97dc1052697342de5e9723a6e0dcc312a684da4c5e7383230cec94c097857df8a76c1620"

	// TLS HexDump Data
	// Ethernet data
	// dst --> b4:1c:30:c0:45:92
	// src --> c4:d9:87:86:1a:0f

	// IPv4 data
	// src --> 192.168.0.142
	// dst --> 104.18.113.58
	// Protocol --> TCP
	// TTL --> 64
	// Id --> 58867

	// TCP data
	// src --> 49204
	// dst --> 443
	// PSH --> true ; ACK --> true
	// Window --> 501
	// Urgent --> 0

	// TLS data
	// Record Layers (2)
	// 1. Change Cipher Spec Protocol --> Change Cipher Spec
	// 		Content-Type --> 20
	// 		Version --> TLS 1.2
	// 		Length --> 1
	// 		Message --> 1
	// 2. Application Data Protocol --> http-over-tls
	// 		Content-Type --> 23
	// 		Version --> TLS 1.2
	// 		Length --> 53
	// 		Payload --> hexdump of byte payload

	data, err := hex.DecodeString(tlsHexDump)

	if err != nil {
		panic(err)
	}

	ethpacket := gopacket.NewPacket(data,
		layers.LayerTypeEthernet,
		gopacket.Default)

	return ethpacket
}

func constructUDPPacket() gopacket.Packet {

	ethLayer, ipLayer := getBaseLayers()
	ipLayer.Protocol = layers.IPProtocolUDP
	udpLayer := getUDPLayer()

	return constructPacket(ethLayer, ipLayer, udpLayer)
}

func constructTCPpacket() gopacket.Packet {

	ethLayer, ipLayer := getBaseLayers()
	ipLayer.Protocol = layers.IPProtocolTCP
	tcpLayer := getTCPLayer()
	return constructPacket(ethLayer, ipLayer, tcpLayer)
}

func TestDecodeEthernetFrame(t *testing.T) {
	packet := constructTCPpacket()

	layer := packet.Layer(layers.LayerTypeEthernet)
	ethLayer := layer.(*layers.Ethernet)

	data := PacketData{}

	DecodeEthernetFrame(ethLayer, &data)

	t.Run("test data is updated with ethernet data", func(t *testing.T) {
		ethFrame := data.EthernetFrame
		if ethFrame.SrcMac != "ff:aa:fa:aa:ff:aa" {
			t.Errorf("source mac address does not exist.")
		}

		if ethFrame.DstMac != "bd:bd:bd:bd:bd:bd" {
			t.Errorf("destination mac address does not exist.")
		}
	})
}

func TestDecodeNetworkLayer(t *testing.T) {
	packet := constructTCPpacket()

	t.Run("test data contains ip packet data", func(t *testing.T) {

		layer := packet.Layer(layers.LayerTypeIPv4)
		ipLayer := layer.(*layers.IPv4)

		data := PacketData{}

		DecodeNetworkLayer(ipLayer, &data)

		ipData := data.Network

		if ipData == nil {
			t.Errorf("IP data not found")
		}

		if ipData.SrcIP != "127.0.0.1" {
			t.Errorf("source ip address not found.")
		}

		if ipData.DstIP != "8.8.8.8" {
			t.Errorf("destination ip address not found.")
		}

		if ipData.Protocol != "TCP" {
			t.Errorf("protocol invalid for ip data")
		}
	})

	t.Run("test that network section for data returns nil if iplayer is nil", func(t *testing.T) {
		data := PacketData{}

		DecodeNetworkLayer(nil, &data)

		if data.Network != nil {
			t.Errorf("network section should return nil.")
		}
	})
}

func TestDecodeTransportLayer(t *testing.T) {

	t.Run("test data contains tcp packet data", func(t *testing.T) {
		packet := constructTCPpacket()
		layer := packet.Layer(layers.LayerTypeTCP)
		tcpLayer := layer.(*layers.TCP)

		layerTypes := []gopacket.LayerType{layers.LayerTypeTCP}

		data := PacketData{}

		src, dst := packet.TransportLayer().TransportFlow().Endpoints()

		DecodeTransportLayer(src, dst, nil, tcpLayer, &data, layerTypes)

		if data.Transport == nil {
			t.Errorf("Transport section not found")
		}

		port := "4321"
		tType := "TCP"

		if data.Transport.Type != tType {
			t.Errorf("Unexpected transport type, expected TCP")
		}

		if data.Transport.SrcPort != port {
			t.Errorf("Unexpected source port for TCP transport")
		}

	})

	t.Run("test data contains udp packet data", func(t *testing.T) {
		packet := constructUDPPacket()
		layer := packet.Layer(layers.LayerTypeUDP)
		udpLayer := layer.(*layers.UDP)

		layerTypes := []gopacket.LayerType{layers.LayerTypeUDP}

		data := PacketData{}

		src, dst := packet.TransportLayer().TransportFlow().Endpoints()

		DecodeTransportLayer(src, dst, udpLayer, nil, &data, layerTypes)

		if data.Transport == nil {
			t.Errorf("Transport section not found")
		}

		port := "4000"
		tType := "UDP"

		if data.Transport.Type != tType {
			t.Errorf("Unexpected transport type, expected UDP")
		}

		if data.Transport.SrcPort != port {
			t.Errorf("Unexpected source port for UDP transport")
		}

	})
}

func TestDecodePacket(t *testing.T) {
	packet := constructTCPpacket()

	payload, err := DecodePacket(packet)

	if err != nil {
		panic(err)
	}

	t.Run("test for known nil fields", func(t *testing.T) {
		application := payload.Application
		if application != nil {
			t.Errorf("test for application layer failed, expected nil value got %v", application)
		}
	})

	t.Run("check for ethernet data", func(t *testing.T) {
		got := payload.EthernetFrame.SrcMac
		expected := "ff:aa:fa:aa:ff:aa"
		if got != expected {
			t.Errorf("test for ethernet layer failed, Source Mac Addresses do not match.")
		}
	})

	t.Run("check for ip data", func(t *testing.T) {
		got := payload.Network.SrcIP
		log.Println(got)
		expected := "127.0.0.1"
		if got != expected {
			t.Errorf("test for ip layer failed, IP addresses do not match")
		}
	})

	t.Run("check for TCP data", func(t *testing.T) {
		got := payload.Transport.SrcPort
		expected := "4321"
		if got != expected {
			t.Errorf("test for tcp layer failed, Source Ports do not match")
		}
	})
}

func TestDecodePacketTLS(t *testing.T) {
	packet := constructTLSPacket()

	payload, err := DecodePacket(packet)
	if err != nil {
		panic(err)
	}

	t.Run("test for AppData record", func(t *testing.T) {
		appRecord := (*payload.Application.TLS.AppData)[0]

		header := appRecord.Header

		if header.ContentType != "Application Data" {
			t.Errorf("Content-Type does not match for app record.")
		}

		if header.Length != 53 {
			t.Errorf("Header length does not match.")
		}

		if header.Version != "TLS 1.2" {
			t.Errorf("Version does not match.")
		}
	})

	t.Run("test for ChangeCipherSpec record", func(t *testing.T) {
		cipherRecord := (*payload.Application.TLS.ChangeCipherSpec)[0]

		header := cipherRecord.Header
		message := cipherRecord.Message

		// Test for ApplicationData record
		if header.ContentType != "Change Cipher Spec" {
			t.Errorf("Content-Type does not match for cipher spec record.")
		}

		if header.Length != 1 {
			t.Errorf("Header length does not match.")
		}

		if header.Version != "TLS 1.2" {
			t.Errorf("Version does not match.")
		}

		// Test for ChangeCipherSpec record
		if message != 1 {
			t.Errorf("Message value does not match")
		}
	})
}

func TestErrorDecodePacket(t *testing.T) {

	t.Run("test that packet is empty", func(t *testing.T) {
		emptyPacket := []byte{}

		ethpacket := gopacket.NewPacket(emptyPacket,
			layers.LayerTypeEthernet,
			gopacket.Default)

		_, err := DecodePacket(ethpacket)

		if err == nil {
			t.Errorf("Error decoding Ethernet packet")
		}
	})
}
