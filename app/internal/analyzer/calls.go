package analyzer

import (
	"sort"
	"time"

	"github.com/alirezarajaee/callquality-ai/app/internal/sip"
)

type CallState string

const (
	CallStateUnknown     CallState = "UNKNOWN"
	CallStateRinging     CallState = "RINGING"
	CallStateEstablished CallState = "ESTABLISHED"
	CallStateCompleted   CallState = "COMPLETED"
	CallStateFailed      CallState = "FAILED"
	CallStateIncomplete  CallState = "INCOMPLETE"
)

type SignalingEvent struct {
	PacketNumber int
	Timestamp    time.Time

	MessageType sip.MessageType

	Method     string
	StatusCode int

	CSeqNumber int
	CSeqMethod string
}

type Call struct {
	CallID string

	From string
	To   string

	FromTag string
	ToTag   string

	StartTime     time.Time
	RingingTime   time.Time
	ConnectedTime time.Time
	EndTime       time.Time

	SetupDuration time.Duration
	Duration      time.Duration

	State CallState

	FinalResponseCode int

	HasInvite  bool
	HasRinging bool
	HasOK      bool
	HasACK     bool
	HasBYE     bool

	Messages []SignalingEvent

	MediaEndpoints []MediaEndpoint

	RTPStreams []RTPStreamResult
}

func ReconstructCalls(packets []AnalyzedPacket) []Call {
	ordered := append([]AnalyzedPacket(nil), packets...)

	sort.SliceStable(ordered, func(i, j int) bool {
		left := ordered[i].Packet.Timestamp
		right := ordered[j].Packet.Timestamp

		if left.Equal(right) {
			return ordered[i].Packet.Number <
				ordered[j].Packet.Number
		}

		return left.Before(right)
	})

	callsByID := make(map[string]*Call)

	for _, packet := range ordered {
		message := packet.SIPMessage

		if !message.Detection.IsSIP {
			continue
		}

		if message.CallID == "" {
			continue
		}

		call, exists := callsByID[message.CallID]
		if !exists {
			call = &Call{
				CallID: message.CallID,
				State:  CallStateUnknown,
			}

			callsByID[message.CallID] = call
		}

		event := SignalingEvent{
			PacketNumber: packet.Packet.Number,
			Timestamp:    packet.Packet.Timestamp,
			MessageType:  message.Detection.MessageType,
			Method:       message.Detection.Method,
			StatusCode:   message.Detection.StatusCode,
			CSeqNumber:   message.CSeqNumber,
			CSeqMethod:   message.CSeqMethod,
		}

		call.Messages = append(call.Messages, event)

		captureSDP(call, message)

		switch {
		case isRequest(message, "INVITE"):
			handleInviteRequest(
				call,
				message,
				packet.Packet.Timestamp,
			)

		case isResponseTo(message, "INVITE", 180):
			handleRinging(
				call,
				packet.Packet.Timestamp,
			)

		case isResponseTo(message, "INVITE", 200):
			handleConnected(
				call,
				packet.Packet.Timestamp,
			)

		case isResponseToInviteFailure(message):
			handleInviteFailure(
				call,
				message.Detection.StatusCode,
				packet.Packet.Timestamp,
			)

		case isRequest(message, "ACK"):
			call.HasACK = true

		case isRequest(message, "BYE"):
			handleBye(
				call,
				packet.Packet.Timestamp,
			)
		}
	}

	calls := make([]Call, 0, len(callsByID))

	for _, call := range callsByID {
		finalizeCall(call)

		if call.HasInvite {
			calls = append(calls, *call)
		}
	}

	sort.SliceStable(calls, func(i, j int) bool {
		return calls[i].StartTime.Before(
			calls[j].StartTime,
		)
	})

	return calls
}

func isRequest(message sip.Message, method string) bool {
	return message.Detection.IsSIP &&
		message.Detection.MessageType == sip.MessageTypeRequest &&
		message.Detection.Method == method
}

func isResponseTo(
	message sip.Message,
	cSeqMethod string,
	statusCode int,
) bool {
	return message.Detection.IsSIP &&
		message.Detection.MessageType == sip.MessageTypeResponse &&
		message.Detection.StatusCode == statusCode &&
		message.CSeqMethod == cSeqMethod
}

func isResponseToInviteFailure(
	message sip.Message,
) bool {
	return message.Detection.IsSIP &&
		message.Detection.MessageType == sip.MessageTypeResponse &&
		message.CSeqMethod == "INVITE" &&
		message.Detection.StatusCode >= 300 &&
		message.Detection.StatusCode <= 699
}

func handleInviteRequest(
	call *Call,
	message sip.Message,
	timestamp time.Time,
) {
	if !call.HasInvite {
		call.HasInvite = true
		call.StartTime = timestamp
		call.From = message.From
		call.To = message.To
		call.FromTag = message.FromTag
		call.ToTag = message.ToTag
	}
}

func handleRinging(
	call *Call,
	timestamp time.Time,
) {
	call.HasRinging = true

	if call.RingingTime.IsZero() {
		call.RingingTime = timestamp
	}

	if call.State == CallStateUnknown {
		call.State = CallStateRinging
	}
}

func handleConnected(
	call *Call,
	timestamp time.Time,
) {
	call.HasOK = true

	if call.ConnectedTime.IsZero() {
		call.ConnectedTime = timestamp
	}

	if !call.StartTime.IsZero() {
		call.SetupDuration =
			call.ConnectedTime.Sub(
				call.StartTime,
			)
	}

	if call.State != CallStateFailed {
		call.State = CallStateEstablished
	}
}

func handleInviteFailure(
	call *Call,
	statusCode int,
	timestamp time.Time,
) {
	if call.FinalResponseCode == 0 {
		call.FinalResponseCode = statusCode
	}

	if call.EndTime.IsZero() {
		call.EndTime = timestamp
	}

	if !call.ConnectedTime.IsZero() {
		return
	}

	call.State = CallStateFailed

	if !call.StartTime.IsZero() {
		call.Duration =
			call.EndTime.Sub(
				call.StartTime,
			)
	}
}

func handleBye(
	call *Call,
	timestamp time.Time,
) {
	call.HasBYE = true

	if call.EndTime.IsZero() {
		call.EndTime = timestamp
	}

	if !call.ConnectedTime.IsZero() {
		call.State = CallStateCompleted

		call.Duration =
			call.EndTime.Sub(
				call.ConnectedTime,
			)
	}
}

func finalizeCall(call *Call) {
	if call.StartTime.IsZero() {
		call.State = CallStateUnknown
		return
	}

	if call.State == CallStateFailed {
		if call.Duration == 0 &&
			!call.EndTime.IsZero() {
			call.Duration =
				call.EndTime.Sub(
					call.StartTime,
				)
		}

		return
	}

	if call.HasBYE &&
		!call.ConnectedTime.IsZero() {
		call.State = CallStateCompleted

		if call.Duration == 0 {
			call.Duration =
				call.EndTime.Sub(
					call.ConnectedTime,
				)
		}

		return
	}

	if !call.ConnectedTime.IsZero() {
		call.State = CallStateEstablished
		return
	}

	call.State = CallStateIncomplete
}