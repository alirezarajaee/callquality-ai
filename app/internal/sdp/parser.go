package sdp

import (
	"fmt"
	"strconv"
	"strings"
)

type ConnectionInfo struct {
	NetworkType string
	AddressType string
	Address     string
}

type CodecInfo struct {
	PayloadType int
	Name        string
	ClockRate   int
	Channels    int
}

type MediaDescription struct {
	MediaType   string
	Port        int
	PortCount   int
	Protocol    string
	PayloadTypes []int

	Connection *ConnectionInfo

	Codecs map[int]CodecInfo

	Direction string
}

type Session struct {
	Version int

	Connection *ConnectionInfo

	Media []MediaDescription

	Direction string
}

func Parse(description string) (Session, error) {
	lines := normalizeLines(description)

	session := Session{
		Version: -1,
		Media:   make([]MediaDescription, 0),
	}

	currentMedia := -1

	for lineNumber, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		if len(line) < 2 || line[1] != '=' {
			return Session{}, fmt.Errorf(
				"invalid SDP line %d: %q",
				lineNumber+1,
				line,
			)
		}

		field := line[0]
		value := line[2:]

		switch field {
		case 'v':
			version, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return Session{}, fmt.Errorf(
					"invalid SDP version on line %d: %w",
					lineNumber+1,
					err,
				)
			}

			session.Version = version

		case 'c':
			connection, err := parseConnection(value)
			if err != nil {
				return Session{}, fmt.Errorf(
					"invalid connection on line %d: %w",
					lineNumber+1,
					err,
				)
			}

			if currentMedia >= 0 {
				session.Media[currentMedia].Connection = &connection
			} else {
				session.Connection = &connection
			}

		case 'm':
			media, err := parseMedia(value)
			if err != nil {
				return Session{}, fmt.Errorf(
					"invalid media description on line %d: %w",
					lineNumber+1,
					err,
				)
			}

			session.Media = append(session.Media, media)
			currentMedia = len(session.Media) - 1

		case 'a':
			if currentMedia >= 0 {
				handleMediaAttribute(
					&session.Media[currentMedia],
					value,
				)
			} else {
				handleSessionAttribute(
					&session,
					value,
				)
			}

		default:
			// Other SDP fields are not required by the initial
			// CallQuality AI implementation and are ignored for now.
		}
	}

	if session.Version < 0 {
		return Session{}, fmt.Errorf("missing SDP version")
	}

	if session.Version != 0 {
		return Session{}, fmt.Errorf(
			"unsupported SDP version: %d",
			session.Version,
		)
	}

	return session, nil
}

func normalizeLines(description string) []string {
	description = strings.ReplaceAll(description, "\r\n", "\n")
	description = strings.ReplaceAll(description, "\r", "\n")

	return strings.Split(description, "\n")
}

func parseConnection(value string) (ConnectionInfo, error) {
	fields := strings.Fields(value)

	if len(fields) < 3 {
		return ConnectionInfo{}, fmt.Errorf(
			"expected \"network-type address-type address\"",
		)
	}

	address := fields[2]

	// Remove multicast TTL / address-count suffixes when present.
	if index := strings.IndexByte(address, '/'); index >= 0 {
		address = address[:index]
	}

	if address == "" {
		return ConnectionInfo{}, fmt.Errorf(
			"empty connection address",
		)
	}

	return ConnectionInfo{
		NetworkType: strings.ToUpper(fields[0]),
		AddressType: strings.ToUpper(fields[1]),
		Address:     address,
	}, nil
}

func parseMedia(value string) (MediaDescription, error) {
	fields := strings.Fields(value)

	if len(fields) < 4 {
		return MediaDescription{}, fmt.Errorf(
			"expected \"media port proto fmt ...\"",
		)
	}

	port, portCount, err := parsePort(fields[1])
	if err != nil {
		return MediaDescription{}, fmt.Errorf(
			"invalid media port %q: %w",
			fields[1],
			err,
		)
	}

	payloadTypes := make([]int, 0, len(fields)-3)

	for _, field := range fields[3:] {
		payloadType, err := strconv.Atoi(field)
		if err != nil {
			// Some non-RTP media protocols use non-numeric
			// formats. Keep the parser tolerant here.
			continue
		}

		payloadTypes = append(payloadTypes, payloadType)
	}

	return MediaDescription{
		MediaType:    strings.ToLower(fields[0]),
		Port:         port,
		PortCount:    portCount,
		Protocol:     fields[2],
		PayloadTypes: payloadTypes,
		Codecs:       make(map[int]CodecInfo),
		Direction:    "",
	}, nil
}

func parsePort(value string) (int, int, error) {
	parts := strings.SplitN(value, "/", 2)

	port, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, err
	}

	if port < 0 || port > 65535 {
		return 0, 0, fmt.Errorf(
			"port out of range: %d",
			port,
		)
	}

	portCount := 1

	if len(parts) == 2 {
		count, err := strconv.Atoi(parts[1])
		if err != nil {
			return 0, 0, err
		}

		if count < 1 {
			return 0, 0, fmt.Errorf(
				"port count must be positive",
			)
		}

		portCount = count
	}

	return port, portCount, nil
}

func handleSessionAttribute(
	session *Session,
	value string,
) {
	name, attributeValue := splitAttribute(value)

	switch strings.ToLower(name) {
	case "sendrecv", "sendonly", "recvonly", "inactive":
		session.Direction = strings.ToLower(name)

		_ = attributeValue
	}
}

func handleMediaAttribute(
	media *MediaDescription,
	value string,
) {
	name, attributeValue := splitAttribute(value)

	switch strings.ToLower(name) {
	case "sendrecv", "sendonly", "recvonly", "inactive":
		media.Direction = strings.ToLower(name)

	case "rtpmap":
		codec, ok := parseRTPMap(attributeValue)
		if !ok {
			return
		}

		media.Codecs[codec.PayloadType] = codec
	}
}

func splitAttribute(value string) (string, string) {
	parts := strings.SplitN(value, ":", 2)

	name := strings.TrimSpace(parts[0])

	if len(parts) == 1 {
		return name, ""
	}

	return name, strings.TrimSpace(parts[1])
}

func parseRTPMap(value string) (CodecInfo, bool) {
	fields := strings.Fields(value)

	if len(fields) != 2 {
		return CodecInfo{}, false
	}

	payloadType, err := strconv.Atoi(fields[0])
	if err != nil {
		return CodecInfo{}, false
	}

	encodingParts := strings.Split(fields[1], "/")

	if len(encodingParts) < 2 {
		return CodecInfo{}, false
	}

	clockRate, err := strconv.Atoi(encodingParts[1])
	if err != nil {
		return CodecInfo{}, false
	}

	channels := 1

	if len(encodingParts) >= 3 {
		channels, err = strconv.Atoi(encodingParts[2])
		if err != nil {
			return CodecInfo{}, false
		}

		if channels < 1 {
			return CodecInfo{}, false
		}
	}

	return CodecInfo{
		PayloadType: payloadType,
		Name:        encodingParts[0],
		ClockRate:   clockRate,
		Channels:    channels,
	}, true
}

func (session Session) EffectiveConnection(
	mediaIndex int,
) *ConnectionInfo {
	if mediaIndex < 0 || mediaIndex >= len(session.Media) {
		return session.Connection
	}

	if session.Media[mediaIndex].Connection != nil {
		return session.Media[mediaIndex].Connection
	}

	return session.Connection
}

func (session Session) EffectiveDirection(
	mediaIndex int,
) string {
	if mediaIndex < 0 || mediaIndex >= len(session.Media) {
		if session.Direction != "" {
			return session.Direction
		}

		return "sendrecv"
	}

	if session.Media[mediaIndex].Direction != "" {
		return session.Media[mediaIndex].Direction
	}

	if session.Direction != "" {
		return session.Direction
	}

	return "sendrecv"
}