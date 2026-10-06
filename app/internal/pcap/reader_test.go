package pcap

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func createTestPCAP(t *testing.T, path string) {
	t.Helper()

	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create test pcap: %v", err)
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)

	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}

	baseTime := time.Unix(1700000000, 0)

	for i := 0; i < 3; i++ {
		data := []byte{
			0x00, 0x11, 0x22, 0x33,
			byte(i), 0x55,
		}

		captureInfo := gopacket.CaptureInfo{
			Timestamp:     baseTime.Add(time.Duration(i) * time.Second),
			CaptureLength: len(data),
			Length:        len(data),
		}

		if err := writer.WritePacket(captureInfo, data); err != nil {
			t.Fatalf("write packet %d: %v", i+1, err)
		}
	}
}

func TestReadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.pcap")

	createTestPCAP(t, path)

	summary, packets, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	if summary.PacketCount != 3 {
		t.Fatalf("expected 3 packets, got %d", summary.PacketCount)
	}

	if len(packets) != 3 {
		t.Fatalf("expected 3 packet records, got %d", len(packets))
	}

	if summary.Duration != 2*time.Second {
		t.Fatalf("expected duration 2s, got %v", summary.Duration)
	}

	if summary.LinkType != "Ethernet" {
		t.Fatalf("expected Ethernet link type, got %q", summary.LinkType)
	}

	if packets[0].Number != 1 {
		t.Fatalf("expected first packet number 1, got %d", packets[0].Number)
	}

	if packets[2].Number != 3 {
		t.Fatalf("expected third packet number 3, got %d", packets[2].Number)
	}
}