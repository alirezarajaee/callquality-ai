package main

import (
	"encoding/binary"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultOutputTargetsRepositorySamples(t *testing.T) {
	want := filepath.Clean(filepath.Join("..", "samples", "synthetic-call.pcap"))
	got := filepath.Clean(defaultOutput)

	if got != want {
		t.Fatalf("default output mismatch: got %q want %q", got, want)
	}
}

func TestDefaultDropRTPIndexPreservesExistingSyntheticCapture(t *testing.T) {
	if defaultDropRTPIndex != 20 {
		t.Fatalf("default drop index changed: got %d want 20", defaultDropRTPIndex)
	}
}

func TestBuildPacketsCanDisableIntentionalLoss(t *testing.T) {
	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	packets := buildPackets(start, -1)

	rtpA := 0
	rtpB := 0
	for _, packet := range packets {
		if packet.sourcePort == rtpPortA && packet.destinationPort == rtpPortB {
			rtpA++
		}
		if packet.sourcePort == rtpPortB && packet.destinationPort == rtpPortA {
			rtpB++
		}
	}

	if rtpA != packetCount {
		t.Fatalf("RTP A->B packet count mismatch: got %d want %d", rtpA, packetCount)
	}
	if rtpB != packetCount {
		t.Fatalf("RTP B->A packet count mismatch: got %d want %d", rtpB, packetCount)
	}
}

func TestRTCPReportsMatchRTPImpairment(t *testing.T) {
	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	assertReports := func(t *testing.T, dropIndex int, wantSentA int, wantFraction uint8, wantCumulative int32) {
		t.Helper()

		packets := buildPackets(start, dropIndex)

		var senderA []byte
		var receiverB []byte
		for _, packet := range packets {
			if packet.sourcePort != rtcpPortA || packet.destinationPort != rtcpPortB {
				continue
			}
			if len(packet.payload) >= 28 && packet.payload[1] == 200 {
				senderA = packet.payload
			}
		}

		for _, packet := range packets {
			if packet.sourcePort != rtcpPortB || packet.destinationPort != rtcpPortA {
				continue
			}
			if len(packet.payload) >= 32 && packet.payload[1] == 201 {
				receiverB = packet.payload
			}
		}

		if senderA == nil {
			t.Fatal("A Sender Report not found")
		}
		if receiverB == nil {
			t.Fatal("B Receiver Report not found")
		}

		gotSentA := int(binary.BigEndian.Uint32(senderA[20:24]))
		if gotSentA != wantSentA {
			t.Fatalf("A Sender Report packet count mismatch: got %d want %d", gotSentA, wantSentA)
		}

		gotFraction := receiverB[12]
		if gotFraction != wantFraction {
			t.Fatalf("A Receiver Report fraction lost mismatch: got %d want %d", gotFraction, wantFraction)
		}

		loss := int32(receiverB[13])<<16 | int32(receiverB[14])<<8 | int32(receiverB[15])
		if gotCumulative := loss; gotCumulative != wantCumulative {
			t.Fatalf("A Receiver Report cumulative loss mismatch: got %d want %d", gotCumulative, wantCumulative)
		}
	}

	// Clean capture: all 50 A->B RTP packets were emitted and RTCP reports zero loss.
	assertReports(t, -1, packetCount, 0, 0)

	// Default capture: exactly one A->B RTP packet is intentionally omitted.
	assertReports(t, defaultDropRTPIndex, packetCount-1, 5, 1)
}

func TestRTCPFractionLost(t *testing.T) {
	cases := []struct {
		name             string
		lost             int
		expected         int
		want             uint8
	}{
		{name: "zero", lost: 0, expected: 50, want: 0},
		{name: "one", lost: 1, expected: 50, want: 5},
		{name: "two", lost: 2, expected: 50, want: 10},
		{name: "all", lost: 50, expected: 50, want: 255},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rtcpFractionLost(tc.lost, tc.expected); got != tc.want {
				t.Fatalf("rtcpFractionLost(%d, %d) = %d, want %d", tc.lost, tc.expected, got, tc.want)
			}
		})
	}
}
