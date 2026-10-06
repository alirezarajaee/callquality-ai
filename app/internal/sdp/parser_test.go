package sdp

import "testing"

func TestParseAudioSDP(t *testing.T) {
	description := "" +
		"v=0\r\n" +
		"o=- 12345 12345 IN IP4 192.168.1.10\r\n" +
		"s=VoIP Call\r\n" +
		"c=IN IP4 192.168.1.10\r\n" +
		"t=0 0\r\n" +
		"a=sendrecv\r\n" +
		"m=audio 4000 RTP/AVP 0 96\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:96 opus/48000/2\r\n"

	session, err := Parse(description)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if session.Version != 0 {
		t.Fatalf(
			"expected version 0, got %d",
			session.Version,
		)
	}

	if session.Connection == nil {
		t.Fatal("expected session-level connection")
	}

	if session.Connection.Address != "192.168.1.10" {
		t.Fatalf(
			"unexpected session address: %q",
			session.Connection.Address,
		)
	}

	if len(session.Media) != 1 {
		t.Fatalf(
			"expected 1 media section, got %d",
			len(session.Media),
		)
	}

	media := session.Media[0]

	if media.MediaType != "audio" {
		t.Fatalf(
			"expected audio media, got %q",
			media.MediaType,
		)
	}

	if media.Port != 4000 {
		t.Fatalf(
			"expected port 4000, got %d",
			media.Port,
		)
	}

	if media.Protocol != "RTP/AVP" {
		t.Fatalf(
			"unexpected protocol: %q",
			media.Protocol,
		)
	}

	if len(media.PayloadTypes) != 2 {
		t.Fatalf(
			"expected 2 payload types, got %d",
			len(media.PayloadTypes),
		)
	}

	pcmu, ok := media.Codecs[0]
	if !ok {
		t.Fatal("expected PCMU codec mapping")
	}

	if pcmu.Name != "PCMU" {
		t.Fatalf(
			"unexpected PCMU name: %q",
			pcmu.Name,
		)
	}

	if pcmu.ClockRate != 8000 {
		t.Fatalf(
			"unexpected PCMU clock rate: %d",
			pcmu.ClockRate,
		)
	}

	opus, ok := media.Codecs[96]
	if !ok {
		t.Fatal("expected Opus codec mapping")
	}

	if opus.Name != "opus" {
		t.Fatalf(
			"unexpected Opus name: %q",
			opus.Name,
		)
	}

	if opus.ClockRate != 48000 {
		t.Fatalf(
			"unexpected Opus clock rate: %d",
			opus.ClockRate,
		)
	}

	if opus.Channels != 2 {
		t.Fatalf(
			"expected 2 Opus channels, got %d",
			opus.Channels,
		)
	}

	if direction := session.EffectiveDirection(0); direction != "sendrecv" {
		t.Fatalf(
			"expected sendrecv direction, got %q",
			direction,
		)
	}
}

func TestMediaConnectionOverridesSessionConnection(t *testing.T) {
	description := "" +
		"v=0\r\n" +
		"o=- 1 1 IN IP4 10.0.0.1\r\n" +
		"s=Test\r\n" +
		"c=IN IP4 10.0.0.1\r\n" +
		"t=0 0\r\n" +
		"m=audio 5000 RTP/AVP 0\r\n" +
		"c=IN IP4 10.0.0.55\r\n"

	session, err := Parse(description)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	connection := session.EffectiveConnection(0)

	if connection == nil {
		t.Fatal("expected effective connection")
	}

	if connection.Address != "10.0.0.55" {
		t.Fatalf(
			"expected media-level address 10.0.0.55, got %q",
			connection.Address,
		)
	}
}

func TestMediaPortCount(t *testing.T) {
	description := "" +
		"v=0\r\n" +
		"o=- 1 1 IN IP4 10.0.0.1\r\n" +
		"s=Test\r\n" +
		"t=0 0\r\n" +
		"m=audio 4000/2 RTP/AVP 0\r\n"

	session, err := Parse(description)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(session.Media) != 1 {
		t.Fatalf(
			"expected 1 media section, got %d",
			len(session.Media),
		)
	}

	media := session.Media[0]

	if media.Port != 4000 {
		t.Fatalf(
			"expected port 4000, got %d",
			media.Port,
		)
	}

	if media.PortCount != 2 {
		t.Fatalf(
			"expected port count 2, got %d",
			media.PortCount,
		)
	}
}

func TestMediaDirectionOverridesSessionDirection(t *testing.T) {
	description := "" +
		"v=0\r\n" +
		"o=- 1 1 IN IP4 10.0.0.1\r\n" +
		"s=Test\r\n" +
		"t=0 0\r\n" +
		"a=sendrecv\r\n" +
		"m=audio 4000 RTP/AVP 0\r\n" +
		"a=recvonly\r\n"

	session, err := Parse(description)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if direction := session.EffectiveDirection(0); direction != "recvonly" {
		t.Fatalf(
			"expected recvonly, got %q",
			direction,
		)
	}
}

func TestRejectMissingVersion(t *testing.T) {
	description := "" +
		"o=- 1 1 IN IP4 10.0.0.1\r\n" +
		"s=Test\r\n" +
		"t=0 0\r\n"

	_, err := Parse(description)

	if err == nil {
		t.Fatal("expected missing version error")
	}
}

func TestRejectUnsupportedVersion(t *testing.T) {
	description := "" +
		"v=1\r\n" +
		"o=- 1 1 IN IP4 10.0.0.1\r\n" +
		"s=Test\r\n" +
		"t=0 0\r\n"

	_, err := Parse(description)

	if err == nil {
		t.Fatal("expected unsupported version error")
	}
}