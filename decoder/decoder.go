package decoder

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Payload struct {
	Source      string
	Destination string
	Protocol    string
	Length      int
	Data        string
}

type NetworkType struct {
	Version  uint8  `json:"version"`
	Length   uint16 `json:"length"`
	Id       uint16 `json:"id"`
	TTL      uint8  `json:"ttl"`
	Protocol string `json:"protocol"`
	Checksum string `json:"checksum"`
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
}

type FlagType struct {
	FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool
}

type TCPTransportType struct {
	Seq        uint32   `json:"seq"`
	Ack        uint32   `json:"ack"`
	DataOffset uint8    `json:"data_offset"`
	Flags      FlagType `json:"flags"`
	Window     uint16   `json:"window"`
	Checksum   uint16   `json:"checksum"`
	Urgent     uint16   `json:"urgent"`
}

type UDPTransportType struct {
	Length uint16 `json:"length"`
}

type TransportType struct {
	Type     string            `json:"type"`
	SrcPort  string            `json:"src_port"`
	DstPort  string            `json:"dst_port"`
	Checksum string            `json:"checksum"`
	Tcp      *TCPTransportType `json:"tcp"`
	Udp      *UDPTransportType `json:"udp"`
}

type EthernetFrameType struct {
	SrcMac string `json:"src_mac"`
	DstMac string `json:"dst_mac"`
}

type CaptureInfo struct {
	Timestamp      time.Time `json:"timestamp"`
	CaptureLength  int       `json:"cap_length"`
	Length         int       `json:"length"`
	InterfaceIndex int       `json:"interface_index"`
}

type TLSRecordHeader struct {
	ContentType string `json:"content_type"`
	Version     string `json:"version"`
	Length      uint16 `json:"length"`
}

type BaseRecord struct {
	Header *TLSRecordHeader `json:"header"`
}

type AppRecord struct {
	BaseRecord
	Payload []byte `json:"payload"`
}

type CipherRecord struct {
	BaseRecord
	Message uint8 `json:"message"`
}

type HandshakeRecord struct {
	BaseRecord
}

type TLSType struct {
	ChangeCipherSpec *[]CipherRecord    `json:"change_cipher"`
	Handshake        *[]HandshakeRecord `json:"handshake"`
	AppData          *[]AppRecord       `json:"app_data"`
}

type ApplicationType struct {
	TLS *TLSType
}

type PacketData struct {
	Metadata      *CaptureInfo       `json:"metadata"`
	EthernetFrame *EthernetFrameType `json:"ethernet"`
	Network       *NetworkType       `json:"network"`
	Transport     *TransportType     `json:"transport"`
	Application   *ApplicationType   `json:"application"`
}

func DecodePacket(packet gopacket.Packet) (payload PacketData, _ error) {

	var (
		ethLayer layers.Ethernet
		ipLayer  layers.IPv4
		tcpLayer layers.TCP
		udpLayer layers.UDP
		tlsLayer layers.TLS
		dnsLayer layers.DNS
	)

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ethLayer,
		&ipLayer,
		&tcpLayer,
		&tlsLayer,
		&udpLayer,
		&dnsLayer,
	)

	foundLayerTypes := []gopacket.LayerType{}

	data := PacketData{}

	err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)

	if err != nil {
		return PacketData{}, err
	}

	nerr := packet.ErrorLayer()

	if nerr != nil {
		return PacketData{}, nerr.Error()
	}

	// Add Packet Metadata to payload
	data.Metadata = getPacketMetadata(packet)

	// Decode Ethernet data into data.EthernetFrame
	DecodeEthernetFrame(&ethLayer, &data)

	// Decode Network-Layer Data into data.Network
	DecodeNetworkLayer(&ipLayer, &data)

	if packet.TransportLayer() != nil {
		src, dst := packet.TransportLayer().TransportFlow().Endpoints()
		DecodeTransportLayer(src, dst, &udpLayer, &tcpLayer, &data, foundLayerTypes)

		if packet.ApplicationLayer() != nil {
			// Decode Application-Layer into data.Application
			DecodeApplicationLayer(packet, &tlsLayer, &data, foundLayerTypes)
		}
	}

	return data, nil
}

func getPacketMetadata(packet gopacket.Packet) *CaptureInfo {
	cInfo := packet.Metadata().CaptureInfo
	metadata := &CaptureInfo{
		Timestamp:      cInfo.Timestamp,
		CaptureLength:  cInfo.CaptureLength,
		InterfaceIndex: cInfo.InterfaceIndex,
		Length:         cInfo.Length,
	}

	return metadata
}

func DecodeEthernetFrame(ethLayer *layers.Ethernet, data *PacketData) {
	if ethLayer != nil {
		data.EthernetFrame = &EthernetFrameType{
			SrcMac: ethLayer.SrcMAC.String(),
			DstMac: ethLayer.DstMAC.String(),
		}
	}
}

func DecodeNetworkLayer(ipLayer *layers.IPv4, data *PacketData) {
	if ipLayer != nil {
		data.Network = &NetworkType{
			SrcIP:    ipLayer.SrcIP.String(),
			DstIP:    ipLayer.DstIP.String(),
			Length:   ipLayer.Length,
			Id:       ipLayer.Id,
			TTL:      ipLayer.TTL,
			Version:  ipLayer.Version,
			Protocol: ipLayer.Protocol.String(),
			Checksum: "dummy checksum",
		}
	}
}

func DecodeTransportLayer(src gopacket.Endpoint, dst gopacket.Endpoint, udpLayer *layers.UDP, tcpLayer *layers.TCP, data *PacketData, foundLayerTypes []gopacket.LayerType) {

	tType := &TransportType{
		SrcPort: src.String(),
		DstPort: dst.String(),
	}

	for _, layerType := range foundLayerTypes {
		switch layerType {
		case layers.LayerTypeUDP:
			tType.Type = "UDP"
			tData := decodeUDP(udpLayer)
			tType.Udp = tData
		case layers.LayerTypeTCP:
			tType.Type = "TCP"
			tData := decodeTCP(tcpLayer)
			tType.Tcp = tData
		}
	}

	data.Transport = tType
}

func decodeTCP(tcpLayer *layers.TCP) *TCPTransportType {

	if tcpLayer != nil {
		return &TCPTransportType{
			Window:     tcpLayer.Window,
			Urgent:     tcpLayer.Urgent,
			Seq:        tcpLayer.Seq,
			Ack:        tcpLayer.Ack,
			DataOffset: tcpLayer.DataOffset,
			Flags: FlagType{
				SYN: tcpLayer.SYN,
				PSH: tcpLayer.PSH,
				FIN: tcpLayer.FIN,
				RST: tcpLayer.RST,
				URG: tcpLayer.URG,
				ECE: tcpLayer.ECE,
				CWR: tcpLayer.CWR,
				ACK: tcpLayer.ACK,
			},
		}
	}

	return nil
}

func decodeUDP(udpLayer *layers.UDP) *UDPTransportType {

	if udpLayer != nil {
		return &UDPTransportType{
			Length: udpLayer.Length,
		}
	}

	return nil
}

func getAppData(appData []layers.TLSAppDataRecord) []AppRecord {
	appDataList := []AppRecord{}

	for _, item := range appData {
		appDataList = append(appDataList, AppRecord{
			BaseRecord: BaseRecord{
				Header: &TLSRecordHeader{
					Version:     item.Version.String(),
					Length:      item.Length,
					ContentType: item.ContentType.String(),
				},
			},
			Payload: item.Payload,
		})
	}

	return appDataList
}

func getHandshakeData(handshakeRecord []layers.TLSHandshakeRecord) []HandshakeRecord {
	appDataList := []HandshakeRecord{}

	for _, item := range handshakeRecord {
		appDataList = append(appDataList, HandshakeRecord{
			BaseRecord: BaseRecord{
				Header: &TLSRecordHeader{
					Version:     item.Version.String(),
					Length:      item.Length,
					ContentType: item.ContentType.String(),
				},
			},
		})
	}

	return appDataList
}

func getCipherData(cipherRecord []layers.TLSChangeCipherSpecRecord) []CipherRecord {
	appDataList := []CipherRecord{}

	for _, item := range cipherRecord {
		appDataList = append(appDataList, CipherRecord{
			BaseRecord: BaseRecord{
				Header: &TLSRecordHeader{
					Version:     item.Version.String(),
					Length:      item.Length,
					ContentType: item.ContentType.String(),
				},
			},
			Message: uint8(item.Message),
		})
	}

	return appDataList
}

func decodeTLS(tlsLayer *layers.TLS) *TLSType {
	tlsData := &TLSType{}

	appData := getAppData(tlsLayer.AppData)
	handshakeData := getHandshakeData(tlsLayer.Handshake)
	cipherData := getCipherData(tlsLayer.ChangeCipherSpec)

	if len(appData) != 0 {
		tlsData.AppData = &appData
	}
	if len(handshakeData) != 0 {
		tlsData.Handshake = &handshakeData
	}
	if len(cipherData) != 0 {
		tlsData.ChangeCipherSpec = &cipherData
	}

	return tlsData
}

func decodeDNS() {}

func decodeHTTP() {}

func DecodeApplicationLayer(packet gopacket.Packet, tlsLayer *layers.TLS, data *PacketData, foundLayerTypes []gopacket.LayerType) {

	var application *ApplicationType = &ApplicationType{}

	if tlsLayer != nil {
		tlsData := decodeTLS(tlsLayer)
		application.TLS = tlsData
	}

	// Check if TCP port is 80, decode as HTTP if there is data.

	// Check if there is a DNS Layer too and decode it.

	data.Application = application
}
