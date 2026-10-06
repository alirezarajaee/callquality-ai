package sip

import (
	"strconv"
	"strings"
)

type Message struct {
	Detection DetectionResult

	Headers map[string]string

	CallID string

	From string
	To   string

	FromTag string
	ToTag   string

	CSeqNumber int
	CSeqMethod string

	Via string

	Contact string

	ContentType   string
	ContentLength int

	Body string
}

func ParseMessage(
	payload []byte,
	sourcePort uint16,
	destinationPort uint16,
) (Message, bool) {
	detection := Detect(
		payload,
		sourcePort,
		destinationPort,
	)

	if !detection.IsSIP {
		return Message{}, false
	}

	text := normalizeMessage(string(payload))

	headerText, body := splitHeaderBody(text)

	lines := strings.Split(headerText, "\n")

	result := Message{
		Detection: detection,
		Headers:   make(map[string]string),
		Body:      body,
	}

	for _, rawLine := range lines[1:] {
		line := strings.TrimSpace(rawLine)

		if line == "" {
			continue
		}

		name, value, ok := splitHeader(line)
		if !ok {
			continue
		}

		canonicalName := canonicalHeaderName(name)
		result.Headers[canonicalName] = value

		switch canonicalName {
		case "Call-ID":
			result.CallID = value

		case "From":
			result.From = value
			result.FromTag = extractTag(value)

		case "To":
			result.To = value
			result.ToTag = extractTag(value)

		case "CSeq":
			result.CSeqNumber, result.CSeqMethod = parseCSeq(value)

		case "Via":
			result.Via = value

		case "Contact":
			result.Contact = value

		case "Content-Type":
			result.ContentType = value

		case "Content-Length":
			result.ContentLength = parseInteger(value)
		}
	}

	return result, true
}

func normalizeMessage(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")

	return value
}

func splitHeaderBody(message string) (string, string) {
	parts := strings.SplitN(message, "\n\n", 2)

	if len(parts) == 1 {
		return parts[0], ""
	}

	return parts[0], parts[1]
}

func splitHeader(line string) (string, string, bool) {
	index := strings.IndexByte(line, ':')

	if index <= 0 {
		return "", "", false
	}

	name := strings.TrimSpace(line[:index])
	value := strings.TrimSpace(line[index+1:])

	return name, value, true
}

func canonicalHeaderName(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "call-id", "i":
		return "Call-ID"

	case "from", "f":
		return "From"

	case "to", "t":
		return "To"

	case "cseq":
		return "CSeq"

	case "via", "v":
		return "Via"

	case "contact", "m":
		return "Contact"

	case "content-type", "c":
		return "Content-Type"

	case "content-length", "l":
		return "Content-Length"

	default:
		return strings.TrimSpace(name)
	}
}

func extractTag(value string) string {
	lower := strings.ToLower(value)

	index := strings.Index(lower, ";tag=")
	if index == -1 {
		return ""
	}

	tag := value[index+5:]

	if semicolon := strings.IndexByte(tag, ';'); semicolon >= 0 {
		tag = tag[:semicolon]
	}

	if space := strings.IndexAny(tag, " \t"); space >= 0 {
		tag = tag[:space]
	}

	return strings.TrimSpace(tag)
}

func parseCSeq(value string) (int, string) {
	fields := strings.Fields(value)

	if len(fields) != 2 {
		return 0, ""
	}

	number, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, ""
	}

	return number, strings.ToUpper(fields[1])
}

func parseInteger(value string) int {
	number, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0
	}

	return number
}