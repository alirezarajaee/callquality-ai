package pcap

import (
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type DecodedPacket struct {
	Layers []string

	SourceIP      string
	DestinationIP string

	TransportProtocol string

	SourcePort      uint16
	DestinationPort uint16

	Payload       []byte
	PayloadLength int

	HasIPv4 bool
	HasIPv6 bool
	HasTCP  bool
	HasUDP  bool
}

func DecodePacket(data []byte, linkType layers.LinkType) DecodedPacket {
	decoder := linkTypeToLayerType(linkType)

	packet := gopacket.NewPacket(
		data,
		decoder,
		gopacket.Default,
	)

	result := DecodedPacket{}

	for _, layer := range packet.Layers() {
		result.Layers = append(
			result.Layers,
			layer.LayerType().String(),
		)
	}

	if networkLayer := packet.NetworkLayer(); networkLayer != nil {
		switch layer := networkLayer.(type) {
		case *layers.IPv4:
			result.HasIPv4 = true
			result.SourceIP = normalizeIP(layer.SrcIP)
			result.DestinationIP = normalizeIP(layer.DstIP)

		case *layers.IPv6:
			result.HasIPv6 = true
			result.SourceIP = normalizeIP(layer.SrcIP)
			result.DestinationIP = normalizeIP(layer.DstIP)
		}
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			result.HasTCP = true
			result.TransportProtocol = "TCP"
			result.SourcePort = uint16(tcp.SrcPort)
			result.DestinationPort = uint16(tcp.DstPort)

			result.Payload = append([]byte(nil), tcp.Payload...)
			result.PayloadLength = len(result.Payload)
		}
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if udp, ok := udpLayer.(*layers.UDP); ok {
			result.HasUDP = true
			result.TransportProtocol = "UDP"
			result.SourcePort = uint16(udp.SrcPort)
			result.DestinationPort = uint16(udp.DstPort)

			result.Payload = append([]byte(nil), udp.Payload...)
			result.PayloadLength = len(result.Payload)
		}
	}

	return result
}

func linkTypeToLayerType(linkType layers.LinkType) gopacket.LayerType {
	switch linkType {
	case layers.LinkTypeEthernet:
		return layers.LayerTypeEthernet
	default:
		return linkType.LayerType()
	}
}

func normalizeIP(ip net.IP) string {
	if ip == nil {
		return ""
	}

	return ip.String()
}