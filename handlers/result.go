// Package handlers provides result types for handler responses.
package handlers

import (
	"codeberg.org/miekg/dns"
)

// HandlerStatus represents the result of a handler's processing attempt.
type HandlerStatus uint8

const (
	// StatusProcessed indicates the handler successfully processed the packet
	// and the response should be sent to the client.
	StatusProcessed HandlerStatus = iota

	// StatusNotRelevant indicates the handler determined this packet is not
	// relevant to its protocol (e.g., UPDATE without UPDATE-LEASE EDNS option).
	// The router should apply a fallback action (e.g., default forward).
	StatusNotRelevant

	// StatusError indicates the handler encountered an error.
	// The response contains error details and should be sent to the client.
	StatusError
)

// String returns a human-readable name for the status.
func (s HandlerStatus) String() string {
	switch s {
	case StatusProcessed:
		return "Processed"
	case StatusNotRelevant:
		return "NotRelevant"
	case StatusError:
		return "Error"
	default:
		return "Unknown"
	}
}

// HandlerResult encapsulates a handler's response and status code.
type HandlerResult struct {
	// Status indicates whether the packet was processed or if router should take fallback action.
	Status HandlerStatus

	// Message is the DNS response message.
	// For StatusProcessed or StatusError, this is sent to the client.
	// For StatusNotRelevant, this may be nil (router will use default action).
	Message *dns.Msg

	// Reason is a human-readable explanation of the status (useful for logging).
	Reason string

	// Error is the underlying error (if any).
	Error error
}

// NewProcessedResult creates a result indicating successful processing.
func NewProcessedResult(msg *dns.Msg) *HandlerResult {
	return &HandlerResult{
		Status:  StatusProcessed,
		Message: msg,
		Reason:  "Handler processed packet successfully",
	}
}

// NewNotRelevantResult creates a result indicating the packet is not relevant to this handler.
func NewNotRelevantResult(reason string) *HandlerResult {
	return &HandlerResult{
		Status:  StatusNotRelevant,
		Message: nil,
		Reason:  reason,
	}
}

// NewErrorResult creates a result indicating an error occurred.
func NewErrorResult(msg *dns.Msg, reason string, err error) *HandlerResult {
	return &HandlerResult{
		Status:  StatusError,
		Message: msg,
		Reason:  reason,
		Error:   err,
	}
}
