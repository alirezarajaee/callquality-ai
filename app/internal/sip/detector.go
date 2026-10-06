package sip

import (
	"strconv"
	"strings"
)

type MessageType string

const (
	MessageTypeUnknown  MessageType = "UNKNOWN"
	MessageTypeRequest  MessageType = "REQUEST"
	MessageTypeResponse MessageType = "RESPONSE"
)

type DetectionResult struct {
	IsSIP        bool
	MessageType  MessageType
	Method       string
	StatusCode   int
	StartLine    string
	PortHint     bool
}

var knownMethods = map[string]struct{}{
	"INVITE":     {},
	"ACK":        {},
	"BYE":        {},
	"CANCEL":     {},
	"OPTIONS":    {},
	"REGISTER":  {},
	"PRACK":      {},
	"SUBSCRIBE": {},
	"NOTIFY":     {},
	"PUBLISH":    {},
	"INFO":       {},
	"REFER":      {},
	"MESSAGE":    {},
	"UPDATE":     {},
}

func Detect(payload []byte, sourcePort, destinationPort uint16) DetectionResult {
	text := strings.TrimSpace(string(payload))
	if text == "" {
		return DetectionResult{
			MessageType: MessageTypeUnknown,
			PortHint:     isSIPPort(sourcePort, destinationPort),
		}
	}

	firstLine := extractFirstLine(text)

	result := DetectionResult{
		MessageType: MessageTypeUnknown,
		StartLine:   firstLine,
		PortHint:    isSIPPort(sourcePort, destinationPort),
	}

	if isSIPResponse(firstLine) {
		statusCode := parseStatusCode(firstLine)

		if statusCode >= 100 && statusCode <= 699 {
			result.IsSIP = true
			result.MessageType = MessageTypeResponse
			result.StatusCode = statusCode
		}

		return result
	}

	method, ok := parseSIPRequest(firstLine)
	if ok {
		result.IsSIP = true
		result.MessageType = MessageTypeRequest
		result.Method = method
	}

	return result
}

func extractFirstLine(message string) string {
	parts := strings.SplitN(message, "\n", 2)

	line := strings.TrimSpace(parts[0])
	line = strings.TrimSuffix(line, "\r")

	return line
}

func isSIPResponse(startLine string) bool {
	return strings.HasPrefix(startLine, "SIP/2.0 ")
}

func parseStatusCode(startLine string) int {
	fields := strings.Fields(startLine)
	if len(fields) < 2 {
		return 0
	}

	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}

	return code
}

func parseSIPRequest(startLine string) (string, bool) {
	fields := strings.Fields(startLine)

	if len(fields) < 3 {
		return "", false
	}

	method := strings.ToUpper(fields[0])
	requestURI := fields[1]
	version := fields[2]

	if version != "SIP/2.0" {
		return "", false
	}

	if _, exists := knownMethods[method]; !exists {
		return "", false
	}

	if !isValidRequestURI(requestURI) {
		return "", false
	}

	return method, true
}

func isValidRequestURI(uri string) bool {
	return strings.HasPrefix(uri, "sip:") ||
		strings.HasPrefix(uri, "sips:") ||
		strings.HasPrefix(uri, "tel:")
}

func isSIPPort(sourcePort, destinationPort uint16) bool {
	return sourcePort == 5060 ||
		sourcePort == 5061 ||
		destinationPort == 5060 ||
		destinationPort == 5061
}