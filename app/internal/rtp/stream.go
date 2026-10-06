package rtp

import "time"

type StreamKey struct {
	SSRC uint32

	SourceIP      string
	DestinationIP string

	SourcePort      uint16
	DestinationPort uint16
}

type ObservedPacket struct {
	Packet      Packet
	ArrivalTime time.Time
	ExtendedSeq int64
}

type StreamStats struct {
	Key StreamKey

	PacketCount int

	UniquePackets     int
	DuplicatePackets  int
	OutOfOrderPackets int

	FirstSequence uint16
	LastSequence  uint16

	FirstTimestamp uint32
	LastTimestamp  uint32

	ExpectedPackets int64
	LostPackets     int64

	LossPercent float64

	JitterAvailable       bool
	JitterClockRate       uint32
	JitterTimestampUnits  float64
	JitterMilliseconds    float64
}

type Stream struct {
	key StreamKey

	initialized bool

	highestExtendedSequence int64
	lastArrivalSequence     int64

	firstExtendedSequence int64
	lastExtendedSequence  int64

	firstSequence uint16
	lastSequence  uint16

	firstTimestamp uint32
	lastTimestamp  uint32

	packetCount       int
	duplicatePackets  int
	outOfOrderPackets int

	seen map[int64]struct{}

	jitter *JitterCalculator
}

func NewStream(key StreamKey) *Stream {
	return &Stream{
		key:  key,
		seen: make(map[int64]struct{}),
	}
}

func (s *Stream) ConfigureJitter(clockRate uint32) error {
	calculator, err := NewJitterCalculator(clockRate)
	if err != nil {
		return err
	}

	s.jitter = calculator

	return nil
}

func (s *Stream) Add(packet Packet, arrivalTime time.Time) {
	extendedSequence := s.extendSequenceNumber(
		packet.SequenceNumber,
	)

	if !s.initialized {
		s.initialized = true

		s.highestExtendedSequence = extendedSequence

		s.lastArrivalSequence = extendedSequence

		s.firstExtendedSequence = extendedSequence
		s.lastExtendedSequence = extendedSequence

		s.firstSequence = packet.SequenceNumber
		s.lastSequence = packet.SequenceNumber

		s.firstTimestamp = packet.Timestamp
		s.lastTimestamp = packet.Timestamp
	} else {
		if extendedSequence > s.highestExtendedSequence {
			s.highestExtendedSequence = extendedSequence
		}

		if extendedSequence > s.lastExtendedSequence {
			s.lastExtendedSequence = extendedSequence
		}

		if extendedSequence < s.lastArrivalSequence {
			if _, duplicate := s.seen[extendedSequence]; !duplicate {
				s.outOfOrderPackets++
			}
		}

		s.lastArrivalSequence = extendedSequence

		s.lastSequence = packet.SequenceNumber
		s.lastTimestamp = packet.Timestamp
	}

	s.packetCount++

	if _, exists := s.seen[extendedSequence]; exists {
		s.duplicatePackets++
		return
	}

	s.seen[extendedSequence] = struct{}{}

	if s.jitter != nil {
		s.jitter.Add(
			packet.Timestamp,
			arrivalTime,
		)
	}
}

func (s *Stream) Stats() StreamStats {
	stats := StreamStats{
		Key:                s.key,
		PacketCount:        s.packetCount,
		UniquePackets:      len(s.seen),
		DuplicatePackets:   s.duplicatePackets,
		OutOfOrderPackets:  s.outOfOrderPackets,
		FirstSequence:      s.firstSequence,
		LastSequence:       s.lastSequence,
		FirstTimestamp:     s.firstTimestamp,
		LastTimestamp:      s.lastTimestamp,
	}

	if !s.initialized {
		return stats
	}

	stats.ExpectedPackets =
		s.lastExtendedSequence -
			s.firstExtendedSequence +
			1

	if stats.ExpectedPackets < 0 {
		stats.ExpectedPackets = 0
	}

	stats.LostPackets =
		stats.ExpectedPackets -
			int64(stats.UniquePackets)

	if stats.LostPackets < 0 {
		stats.LostPackets = 0
	}

	if stats.ExpectedPackets > 0 {
		stats.LossPercent =
			float64(stats.LostPackets) /
				float64(stats.ExpectedPackets) *
				100
	}

	if s.jitter != nil && s.packetCount >= 2 {
		stats.JitterAvailable = true
		stats.JitterClockRate = s.jitter.ClockRate()
		stats.JitterTimestampUnits = s.jitter.Value()
		stats.JitterMilliseconds = s.jitter.Milliseconds()
	}

	return stats
}

func (s *Stream) extendSequenceNumber(
	sequence uint16,
) int64 {
	if !s.initialized {
		return int64(sequence)
	}

	lastRaw := uint16(
		s.highestExtendedSequence & 0xFFFF,
	)

	difference := int32(sequence) -
		int32(lastRaw)

	if difference > 32767 {
		difference -= 65536
	}

	if difference < -32768 {
		difference += 65536
	}

	return s.highestExtendedSequence +
		int64(difference)
}