package sip

import "testing"

func TestParseInviteMessage(t *testing.T) {
	payload := []byte(
		"INVITE sip:alice@example.com SIP/2.0\r\n" +
			"Via: SIP/2.0/UDP 192.168.1.10:5060\r\n" +
			"From: \"Bob\" <sip:bob@example.com>;tag=from123\r\n" +
			"To: <sip:alice@example.com>\r\n" +
			"Call-ID: call-001@example.com\r\n" +
			"CSeq: 1 INVITE\r\n" +
			"Contact: <sip:bob@192.168.1.10:5060>\r\n" +
			"Content-Type: application/sdp\r\n" +
			"Content-Length: 7\r\n" +
			"\r\n" +
			"SDPTEST",
	)

	message, ok := ParseMessage(payload, 5060, 5060)

	if !ok {
		t.Fatal("expected SIP message")
	}

	if message.CallID != "call-001@example.com" {
		t.Fatalf(
			"unexpected Call-ID: %q",
			message.CallID,
		)
	}

	if message.FromTag != "from123" {
		t.Fatalf(
			"unexpected From tag: %q",
			message.FromTag,
		)
	}

	if message.ToTag != "" {
		t.Fatalf(
			"expected empty To tag, got %q",
			message.ToTag,
		)
	}

	if message.CSeqNumber != 1 {
		t.Fatalf(
			"expected CSeq number 1, got %d",
			message.CSeqNumber,
		)
	}

	if message.CSeqMethod != "INVITE" {
		t.Fatalf(
			"expected CSeq method INVITE, got %q",
			message.CSeqMethod,
		)
	}

	if message.ContentType != "application/sdp" {
		t.Fatalf(
			"unexpected Content-Type: %q",
			message.ContentType,
		)
	}

	if message.ContentLength != 7 {
		t.Fatalf(
			"expected Content-Length 7, got %d",
			message.ContentLength,
		)
	}

	if message.Body != "SDPTEST" {
		t.Fatalf(
			"unexpected body: %q",
			message.Body,
		)
	}
}

func TestParseShortHeaders(t *testing.T) {
	payload := []byte(
		"ACK sip:alice@example.com SIP/2.0\r\n" +
			"v: SIP/2.0/UDP 192.168.1.10:5060\r\n" +
			"f: <sip:bob@example.com>;tag=abc\r\n" +
			"t: <sip:alice@example.com>;tag=xyz\r\n" +
			"i: call-002@example.com\r\n" +
			"CSeq: 2 ACK\r\n" +
			"l: 0\r\n" +
			"\r\n",
	)

	message, ok := ParseMessage(payload, 5060, 5060)

	if !ok {
		t.Fatal("expected SIP message")
	}

	if message.CallID != "call-002@example.com" {
		t.Fatalf(
			"unexpected Call-ID: %q",
			message.CallID,
		)
	}

	if message.FromTag != "abc" {
		t.Fatalf(
			"unexpected From tag: %q",
			message.FromTag,
		)
	}

	if message.ToTag != "xyz" {
		t.Fatalf(
			"unexpected To tag: %q",
			message.ToTag,
		)
	}
}