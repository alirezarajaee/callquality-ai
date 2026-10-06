package analyzer

import (
	"testing"

	"github.com/alirezarajaee/callquality-ai/app/internal/sip"
)

func TestCaptureSDP(t *testing.T) {
	call := &Call{
		CallID: "media-test-call",
	}

	message := sip.Message{
		ContentType: "application/sdp",

		Body: "" +
			"v=0\r\n" +
			"o=- 12345 12345 IN IP4 192.168.1.10\r\n" +
			"s=VoIP Call\r\n" +
			"c=IN IP4 192.168.1.10\r\n" +
			"t=0 0\r\n" +
			"a=sendrecv\r\n" +
			"m=audio 4000 RTP/AVP 0 96\r\n" +
			"a=rtpmap:0 PCMU/8000\r\n" +
			"a=rtpmap:96 opus/48000/2\r\n",
	}

	captureSDP(call, message)

	if len(call.MediaEndpoints) != 1 {
		t.Fatalf(
			"expected 1 media endpoint, got %d",
			len(call.MediaEndpoints),
		)
	}

	endpoint := call.MediaEndpoints[0]

	if endpoint.MediaType != "audio" {
		t.Fatalf(
			"expected audio media, got %q",
			endpoint.MediaType,
		)
	}

	if endpoint.Address != "192.168.1.10" {
		t.Fatalf(
			"unexpected media address: %q",
			endpoint.Address,
		)
	}

	if endpoint.Port != 4000 {
		t.Fatalf(
			"expected media port 4000, got %d",
			endpoint.Port,
		)
	}

	if endpoint.Protocol != "RTP/AVP" {
		t.Fatalf(
			"unexpected media protocol: %q",
			endpoint.Protocol,
		)
	}

	if endpoint.Direction != "sendrecv" {
		t.Fatalf(
			"expected sendrecv direction, got %q",
			endpoint.Direction,
		)
	}

	if len(endpoint.PayloadTypes) != 2 {
		t.Fatalf(
			"expected 2 payload types, got %d",
			len(endpoint.PayloadTypes),
		)
	}

	if _, ok := endpoint.Codecs[0]; !ok {
		t.Fatal("expected PCMU codec")
	}

	if _, ok := endpoint.Codecs[96]; !ok {
		t.Fatal("expected Opus codec")
	}
}

func TestCaptureSDPDeduplicatesEndpoint(t *testing.T) {
	call := &Call{
		CallID: "dedupe-test",
	}

	message := sip.Message{
		ContentType: "application/sdp",

		Body: "" +
			"v=0\r\n" +
			"o=- 1 1 IN IP4 192.168.1.10\r\n" +
			"s=Test\r\n" +
			"c=IN IP4 192.168.1.10\r\n" +
			"t=0 0\r\n" +
			"m=audio 4000 RTP/AVP 0\r\n" +
			"a=rtpmap:0 PCMU/8000\r\n",
	}

	captureSDP(call, message)
	captureSDP(call, message)

	if len(call.MediaEndpoints) != 1 {
		t.Fatalf(
			"expected duplicate endpoint to be removed, got %d",
			len(call.MediaEndpoints),
		)
	}
}

func TestCaptureSDPIgnoresNonSDP(t *testing.T) {
	call := &Call{
		CallID: "non-sdp-test",
	}

	message := sip.Message{
		ContentType: "application/json",
		Body:        `{"hello":"world"}`,
	}

	captureSDP(call, message)

	if len(call.MediaEndpoints) != 0 {
		t.Fatalf(
			"expected no media endpoints, got %d",
			len(call.MediaEndpoints),
		)
	}
}

func TestCaptureSDPHandlesInvalidBody(t *testing.T) {
	call := &Call{
		CallID: "invalid-sdp-test",
	}

	message := sip.Message{
		ContentType: "application/sdp",
		Body:        "this is not valid SDP",
	}

	captureSDP(call, message)

	if len(call.MediaEndpoints) != 0 {
		t.Fatalf(
			"expected no media endpoints, got %d",
			len(call.MediaEndpoints),
		)
	}
}