package pcap

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func buildUDPTestPacket(t *testing.T) []byte {
	t.Helper()

	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		SrcIP:    net.IPv4(192, 168, 1, 10),
		DstIP:    net.IPv4(192, 168, 1, 20),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
	}

	udp := &layers.UDP{
		SrcPort: 5000,
		DstPort: 5060,
	}

	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set UDP checksum layer: %v", err)
	}

	payload := gopacket.Payload([]byte("INVITE sip:test@example.com SIP/2.0\r\n"))

	buffer := gopacket.NewSerializeBuffer()

	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(
		buffer,
		options,
		ethernet,
		ip,
		udp,
		payload,
	); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}

	return buffer.Bytes()
}

func TestDecodePacketUDP(t *testing.T) {
	data := buildUDPTestPacket(t)

	result := DecodePacket(data, layers.LinkTypeEthernet)

	if !result.HasIPv4 {
		t.Fatal("expected IPv4 layer")
	}

	if !result.HasUDP {
		t.Fatal("expected UDP layer")
	}

	if result.HasTCP {
		t.Fatal("did not expect TCP layer")
	}

	if result.SourceIP != "192.168.1.10" {
		t.Fatalf(
			"unexpected source IP: got %q",
			result.SourceIP,
		)
	}

	if result.DestinationIP != "192.168.1.20" {
		t.Fatalf(
			"unexpected destination IP: got %q",
			result.DestinationIP,
		)
	}

	if result.TransportProtocol != "UDP" {
		t.Fatalf(
			"unexpected transport protocol: got %q",
			result.TransportProtocol,
		)
	}

	if result.SourcePort != 5000 {
		t.Fatalf(
			"unexpected source port: got %d",
			result.SourcePort,
		)
	}

	if result.DestinationPort != 5060 {
		t.Fatalf(
			"unexpected destination port: got %d",
			result.DestinationPort,
		)
	}

	if result.PayloadLength == 0 {
		t.Fatal("expected non-empty UDP payload")
	}
}