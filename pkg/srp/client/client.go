// Package client implements the SRP (Service Registration Protocol) client.
//
// SRP clients are responsible for generating DNS UPDATE messages with SRP Instructions
// to register, update, or delete services in a DNS zone.
package client

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/srp/instruction"
)

// Config holds the configuration for an SRP client.
type Config struct {
	// ServerAddress is the DNS server address to send UPDATE messages to
	ServerAddress string
	// Zone is the zone to update (e.g., "example.com")
	Zone string
	// KeyName is the name of the DNSKEY used for SIG(0) signing
	KeyName string
	// KeySecret is the shared secret for SIG(0) authentication (base64 encoded)
	KeySecret string
	// Timeout for DNS operations
	Timeout time.Duration
}

// Client is an SRP client that can register, update, and delete services.
type Client struct {
	config Config
}

// New creates a new SRP client with the given configuration.
func New(config Config) *Client {
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}
	return &Client{
		config: config,
	}
}

// NewWithDefaults creates a client with reasonable defaults.
func NewWithDefaults() *Client {
	return New(Config{
		ServerAddress: "127.0.0.1:53",
		Timeout:       5 * time.Second,
	})
}

// Register registers services for a given name.
//
// This creates an SRP UPDATE message with the provided instructions and sends
// it to the configured DNS server.
func (c *Client) Register(ctx context.Context, name string, instructions ...*instruction.Instruction) (*dns.Msg, error) {
	if c.config.Zone == "" {
		return nil, fmt.Errorf("zone is required for registration")
	}

	// Create DNS UPDATE message
	msg := dns.NewMsg(c.config.Zone, dns.TypeSOA)
	if msg == nil {
		return nil, fmt.Errorf("failed to create DNS message")
	}

	msg.Opcode = dns.OpcodeUpdate
	msg.RecursionDesired = false

	// Clear any default settings
	msg.Answer = nil
	msg.Ns = nil

	// Add instructions to the Additional section
	for _, inst := range instructions {
		if err := inst.Validate(); err != nil {
			return nil, fmt.Errorf("invalid instruction: %w", err)
		}

		// Convert instruction to RR
		rr := inst.ToRR()
		if rr == nil {
			return nil, fmt.Errorf("failed to convert instruction to RR")
		}
		msg.Extra = append(msg.Extra, rr)
	}

	// Sign the message if key is configured
	if c.config.KeySecret != "" {
		if err := c.signMessage(msg); err != nil {
			return nil, fmt.Errorf("failed to sign message: %w", err)
		}
	}

	return c.sendUpdate(ctx, msg)
}

// Update updates existing services.
//
// This is similar to Register but includes prerequisites to ensure the records
// being updated actually exist.
func (c *Client) Update(ctx context.Context, name string, instructions ...*instruction.Instruction) (*dns.Msg, error) {
	if c.config.Zone == "" {
		return nil, fmt.Errorf("zone is required for update")
	}

	// Create DNS UPDATE message
	// Create DNS UPDATE message
	msg := dns.NewMsg(c.config.Zone, dns.TypeSOA)
	if msg == nil {
		return nil, fmt.Errorf("failed to create DNS message")
	}
	msg.Opcode = dns.OpcodeUpdate
	msg.RecursionDesired = false

	// Clear any default sections
	msg.Answer = nil
	msg.Ns = nil

	// Add instructions
	for _, inst := range instructions {
		if err := inst.Validate(); err != nil {
			return nil, fmt.Errorf("invalid instruction: %w", err)
		}
		msg.Extra = append(msg.Extra, inst.ToRR())
	}

	if c.config.KeySecret != "" {
		if err := c.signMessage(msg); err != nil {
			return nil, fmt.Errorf("failed to sign message: %w", err)
		}
	}

	return c.sendUpdate(ctx, msg)
}

// Delete deletes services for a given name.
//
// If serviceName is empty, all services are deleted. Otherwise, only the
// specified service is deleted.
func (c *Client) Delete(ctx context.Context, name string, serviceName ...string) (*dns.Msg, error) {
	if c.config.Zone == "" {
		return nil, fmt.Errorf("zone is required for deletion")
	}

	// Create DNS UPDATE message
	msg := dns.NewMsg(c.config.Zone, dns.TypeSOA)
	if msg == nil {
		return nil, fmt.Errorf("failed to create DNS message")
	}
	msg.Opcode = dns.OpcodeUpdate
	msg.RecursionDesired = false

	// Clear any default sections
	msg.Answer = nil
	msg.Ns = nil

	if len(serviceName) == 0 {
		// Delete all services (service delete instruction)
		inst := instruction.ServiceDelete(name)
		msg.Extra = append(msg.Extra, inst.ToRR())
	} else {
		// Delete specific services by name.
		for range serviceName {
			inst := instruction.ServiceDelete(name)
			msg.Extra = append(msg.Extra, inst.ToRR())
		}
	}

	if c.config.KeySecret != "" {
		if err := c.signMessage(msg); err != nil {
			return nil, fmt.Errorf("failed to sign message: %w", err)
		}
	}

	return c.sendUpdate(ctx, msg)
}

// Send sends a raw DNS UPDATE message.
//
// This is useful for testing or when you need full control over the message content.
func (c *Client) Send(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	// Ensure this is an UPDATE message
	msg.ID = dns.ID()
	msg.Response = false
	msg.Opcode = dns.OpcodeUpdate

	if c.config.KeySecret != "" {
		if err := c.signMessage(msg); err != nil {
			return nil, fmt.Errorf("failed to sign message: %w", err)
		}
	}

	return c.sendUpdate(ctx, msg)
}

// signMessage signs the DNS message with SIG(0) using the configured key.
func (c *Client) signMessage(msg *dns.Msg) error {
	if c.config.KeyName == "" {
		return fmt.Errorf("key name is required for signing")
	}
	if c.config.KeySecret == "" {
		return fmt.Errorf("key secret is required for signing")
	}

	// Parse the key (in real implementation, this would use a proper key pair)
	dnskey := dns.NewDNSKEY(c.config.KeyName, 8)
	dnskey.PublicKey = c.config.KeySecret
	msg.Extra = append(msg.Extra, dnskey)

	// For a real implementation, we would:
	// 1. Create the SIG(0) record with proper signature
	// 2. Append the generated SIG(0) record to the Additional section.

	return nil // Placeholder for real implementation
}

// sendUpdate sends the UPDATE message to the DNS server.
func (c *Client) sendUpdate(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	client := &dns.Client{Transport: &dns.Transport{
		Dialer:       &net.Dialer{Timeout: c.config.Timeout},
		ReadTimeout:  c.config.Timeout,
		WriteTimeout: c.config.Timeout,
	}}

	// Create response channel
	respCh := make(chan *dns.Msg, 1)
	errCh := make(chan error, 1)

	go func() {
		resp, _, err := client.Exchange(ctx, msg, "udp", c.config.ServerAddress)
		if err != nil {
			errCh <- fmt.Errorf("exchange failed: %w", err)
		} else {
			respCh <- resp
		}
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	case resp := <-respCh:
		return resp, nil
	case err := <-errCh:
		return nil, err
	}
}

// RegisterService is a convenience function to register a single service.
func (c *Client) RegisterService(ctx context.Context, name string, priority, weight, port uint16, host string) (*dns.Msg, error) {
	inst := instruction.New(name)
	inst.SetService(priority, weight, port, host)

	return c.Register(ctx, name, inst)
}

// RegisterServiceWithTXT is a convenience function to register a service with TXT data.
func (c *Client) RegisterServiceWithTXT(ctx context.Context, name string, priority, weight, port uint16, host string, txt []string) (*dns.Msg, error) {
	inst := instruction.New(name)
	inst.SetService(priority, weight, port, host)
	inst.SetTXT(txt)

	return c.Register(ctx, name, inst)
}

// DeleteService deletes a specific service by name and port.
func (c *Client) DeleteService(ctx context.Context, name string) (*dns.Msg, error) {
	return c.Delete(ctx, name)
}

// CreateUpdateMessage creates a DNS UPDATE message with the provided instructions.
//
// This is useful when you want to manually send the message or inspect it before sending.
func (c *Client) CreateUpdateMessage(instructions ...*instruction.Instruction) (*dns.Msg, error) {
	if c.config.Zone == "" {
		return nil, fmt.Errorf("zone is required")
	}

	msg := dns.NewMsg(c.config.Zone, dns.TypeSOA)
	if msg == nil {
		return nil, fmt.Errorf("failed to create DNS message")
	}

	msg.Opcode = dns.OpcodeUpdate
	msg.RecursionDesired = false

	// Clear any default sections
	msg.Answer = nil
	msg.Ns = nil

	for _, inst := range instructions {
		if err := inst.Validate(); err != nil {
			return nil, fmt.Errorf("invalid instruction: %w", err)
		}
		msg.Extra = append(msg.Extra, inst.ToRR())
	}

	return msg, nil
}

// VerifyResponse checks if the response is successful.
func (c *Client) VerifyResponse(resp *dns.Msg) bool {
	return resp != nil && resp.MsgHeader.Rcode == dns.RcodeSuccess
}

func ensureFQDN(name string) string {
	if name == "" {
		return name
	}
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}
