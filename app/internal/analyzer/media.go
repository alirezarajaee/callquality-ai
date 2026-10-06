package analyzer

import (
	"strings"

	"github.com/alirezarajaee/callquality-ai/app/internal/rtp"
	"github.com/alirezarajaee/callquality-ai/app/internal/sdp"
	"github.com/alirezarajaee/callquality-ai/app/internal/sip"
)

type MediaEndpoint struct {
	MediaIndex int

	MediaType string

	Address string

	Port      int
	PortCount int

	Protocol string

	PayloadTypes []int

	Codecs map[int]sdp.CodecInfo

	Direction string
}

type RTPStreamResult struct {
	Key rtp.StreamKey

	PayloadType uint8

	FirstPacketTimestamp string
	LastPacketTimestamp  string

	Stats rtp.StreamStats
}

func captureSDP(
	call *Call,
	message sip.Message,
) {
	if message.Body == "" {
		return
	}

	contentType := strings.ToLower(
		strings.TrimSpace(
			message.ContentType,
		),
	)

	if !strings.HasPrefix(
		contentType,
		"application/sdp",
	) {
		return
	}

	session, err := sdp.Parse(message.Body)
	if err != nil {
		return
	}

	for index, media := range session.Media {
		if strings.ToLower(
			media.MediaType,
		) != "audio" {
			continue
		}

		connection := session.EffectiveConnection(index)

		if connection == nil {
			continue
		}

		if connection.Address == "" {
			continue
		}

		codecs := make(
			map[int]sdp.CodecInfo,
			len(media.Codecs),
		)

		for payloadType, codec := range media.Codecs {
			codecs[payloadType] = codec
		}

		payloadTypes := append(
			[]int(nil),
			media.PayloadTypes...,
		)

		endpoint := MediaEndpoint{
			MediaIndex: index,

			MediaType: media.MediaType,

			Address: connection.Address,

			Port: media.Port,
			PortCount: media.PortCount,

			Protocol: media.Protocol,

			PayloadTypes: payloadTypes,

			Codecs: codecs,

			Direction: session.EffectiveDirection(index),
		}

		if !mediaEndpointExists(
			call.MediaEndpoints,
			endpoint,
		) {
			call.MediaEndpoints =
				append(
					call.MediaEndpoints,
					endpoint,
				)
		}
	}
}

func mediaEndpointExists(
	endpoints []MediaEndpoint,
	candidate MediaEndpoint,
) bool {
	for _, endpoint := range endpoints {
		if endpoint.MediaType != candidate.MediaType {
			continue
		}

		if endpoint.Address != candidate.Address {
			continue
		}

		if endpoint.Port != candidate.Port {
			continue
		}

		if endpoint.Protocol != candidate.Protocol {
			continue
		}

		return true
	}

	return false
}