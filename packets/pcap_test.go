package packets

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type PcapHandlerTest struct {
	liveConnectionCalled     bool
	liveConnectionCalledWith string
	startSniffingCalled      bool
}

func (pH *PcapHandlerTest) FindAllDevs() ([]pcap.Interface, error) {
	return []pcap.Interface{
		{
			Name: "test device",
		},
	}, nil
}

func (pH *PcapHandlerTest) OpenLiveConnection(deviceName string) (*pcap.Handle, error) {
	pH.liveConnectionCalled = true
	pH.liveConnectionCalledWith = deviceName
	return &pcap.Handle{}, nil
}

func (pH *PcapHandlerTest) startSniffing(handler *pcap.Handle, p PcapMethods, message *SniffMessage) {
	pH.startSniffingCalled = true
}

func (pH *PcapHandlerTest) createPacketSource(handler *pcap.Handle) *gopacket.PacketSource {
	return &gopacket.PacketSource{}
}

func (pH *PcapHandlerTest) getPacketData(packet gopacket.Packet) PacketsData {
	return PacketsData{
		Dst: "192.168.0.0.1",
		Src: "193.553.6.7.1",
	}
}

func TestCheckForDevice(t *testing.T) {
	pcapTest := &PcapHandlerTest{}

	t.Run("should return true if device is found", func(t *testing.T) {
		device := "test device"
		got := checkForDevice(pcapTest, device)
		expected := true

		if got != expected {
			t.Errorf("checkForDevice test failed, expected %v got %v", expected, got)
		}
	})

	t.Run("should return false if device is not found", func(t *testing.T) {
		device := "wrong device"
		got := checkForDevice(pcapTest, device)
		expected := false

		if got != expected {
			t.Errorf("checkForDevice test failed, expected %v got %v", expected, got)
		}
	})
}

func TestStartPacketSniffing(t *testing.T) {
	pcapTest := &PcapHandlerTest{startSniffingCalled: false}
	sniffMessage := &SniffMessage{}
	device := "test device"

	StartPacketSniffing(pcapTest, device, sniffMessage)

	t.Run("called startSniffing", func(t *testing.T) {
		got := pcapTest.startSniffingCalled
		want := true

		if got != want {
			t.Errorf("TestStartPacketSniffing failed, wanted %v got %v", want, got)
		}
	})

	t.Run("called openLiveConnetcion and called with right arguments", func(t *testing.T) {
		called := pcapTest.liveConnectionCalled
		calledWith := pcapTest.liveConnectionCalledWith

		if called != true {
			t.Errorf("openLiveConnection not called, expected %v got %v", called, false)
		}

		if calledWith != device {
			t.Errorf("openLiveConnection called with invalid parameters, expected %s got %s", device, calledWith)
		}
	})
}
