package sip

import "testing"

func TestDetectInvite(t *testing.T) {
	payload := []byte(
		"INVITE sip:alice@example.com SIP/2.0\r\n" +
			"Via: SIP/2.0/UDP 192.168.1.10:5060\r\n" +
			"From: <sip:bob@example.com>\r\n" +
			"To: <sip:alice@example.com>\r\n" +
			"Call-ID: test-call-001\r\n" +
			"CSeq: 1 INVITE\r\n" +
			"Content-Length: 0\r\n" +
			"\r\n",
	)

	result := Detect(payload, 5060, 5060)

	if !result.IsSIP {
		t.Fatal("expected SIP message")
	}

	if result.MessageType != MessageTypeRequest {
		t.Fatalf(
			"expected request, got %s",
			result.MessageType,
		)
	}

	if result.Method != "INVITE" {
		t.Fatalf(
			"expected INVITE, got %q",
			result.Method,
		)
	}

	if result.StatusCode != 0 {
		t.Fatalf(
			"expected status code 0 for request, got %d",
			result.StatusCode,
		)
	}

	if result.StartLine != "INVITE sip:alice@example.com SIP/2.0" {
		t.Fatalf(
			"unexpected start line: %q",
			result.StartLine,
		)
	}

	if !result.PortHint {
		t.Fatal("expected SIP port hint")
	}
}

func TestDetectOKResponse(t *testing.T) {
	payload := []byte(
		"SIP/2.0 200 OK\r\n" +
			"Via: SIP/2.0/UDP 192.168.1.10:5060\r\n" +
			"From: <sip:bob@example.com>\r\n" +
			"To: <sip:alice@example.com>\r\n" +
			"Call-ID: test-call-001\r\n" +
			"CSeq: 1 INVITE\r\n" +
			"Content-Length: 0\r\n" +
			"\r\n",
	)

	result := Detect(payload, 5060, 5060)

	if !result.IsSIP {
		t.Fatal("expected SIP response")
	}

	if result.MessageType != MessageTypeResponse {
		t.Fatalf(
			"expected response, got %s",
			result.MessageType,
		)
	}

	if result.StatusCode != 200 {
		t.Fatalf(
			"expected status code 200, got %d",
			result.StatusCode,
		)
	}

	if result.Method != "" {
		t.Fatalf(
			"expected empty method for response, got %q",
			result.Method,
		)
	}
}

func TestDetectRegister(t *testing.T) {
	payload := []byte(
		"REGISTER sip:example.com SIP/2.0\r\n" +
			"Via: SIP/2.0/UDP 192.168.1.20:5060\r\n" +
			"Content-Length: 0\r\n" +
			"\r\n",
	)

	result := Detect(payload, 15000, 5060)

	if !result.IsSIP {
		t.Fatal("expected SIP message")
	}

	if result.MessageType != MessageTypeRequest {
		t.Fatalf(
			"expected request, got %s",
			result.MessageType,
		)
	}

	if result.Method != "REGISTER" {
		t.Fatalf(
			"expected REGISTER, got %q",
			result.Method,
		)
	}

	if !result.PortHint {
		t.Fatal("expected SIP port hint")
	}
}

func TestRejectNonSIP(t *testing.T) {
	payload := []byte(
		"GET / HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"\r\n",
	)

	result := Detect(payload, 5060, 5060)

	if result.IsSIP {
		t.Fatal("expected non-SIP payload to be rejected")
	}

	if result.MessageType != MessageTypeUnknown {
		t.Fatalf(
			"expected UNKNOWN message type, got %s",
			result.MessageType,
		)
	}
}

func TestRejectMalformedSIPResponse(t *testing.T) {
	payload := []byte("SIP/2.0 hello\r\n\r\n")

	result := Detect(payload, 5060, 5060)

	if result.IsSIP {
		t.Fatal("expected malformed SIP response to be rejected")
	}
}

func TestRejectUnknownMethod(t *testing.T) {
	payload := []byte(
		"HELLO sip:alice@example.com SIP/2.0\r\n" +
			"Content-Length: 0\r\n" +
			"\r\n",
	)

	result := Detect(payload, 5060, 5060)

	if result.IsSIP {
		t.Fatal("expected unknown method to be rejected")
	}
}

func TestSIPWithoutSIPPortHint(t *testing.T) {
	payload := []byte(
		"OPTIONS sip:example.com SIP/2.0\r\n" +
			"Content-Length: 0\r\n" +
			"\r\n",
	)

	result := Detect(payload, 40000, 40001)

	if !result.IsSIP {
		t.Fatal("expected SIP message even without standard SIP ports")
	}

	if result.Method != "OPTIONS" {
		t.Fatalf(
			"expected OPTIONS, got %q",
			result.Method,
		)
	}

	if result.PortHint {
		t.Fatal("did not expect SIP port hint")
	}
}