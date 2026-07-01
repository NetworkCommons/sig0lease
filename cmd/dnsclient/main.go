// Package main implements a simple DNS client for testing.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/NetworkCommons/sig0lease/client"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <server> <command> [args...]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  query <name> [type]        - Send standard DNS query\n")
		fmt.Fprintf(os.Stderr, "  update <zone>              - Send UPDATE query (opcode 5)\n")
		fmt.Fprintf(os.Stderr, "  opcode <name> <type> <op>  - Send query with custom opcode\n")
		os.Exit(1)
	}

	server := os.Args[1]
	command := os.Args[2]

	c := client.New(server, "udp", 5*time.Second)

	switch command {
	case "query":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Usage: %s query <name> [type]\n", os.Args[0])
			os.Exit(1)
		}
		name := os.Args[3]
		qtype := dns.TypeA
		if len(os.Args) > 4 {
			var ok bool
			qtype, ok = dns.StringToType[strings.ToUpper(os.Args[4])]
			if !ok {
				fmt.Fprintf(os.Stderr, "Unknown record type: %s\n", os.Args[4])
				os.Exit(1)
			}
		}
		msg := dns.NewMsg(name, qtype)
		resp, err := c.Query(msg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Query error: %v\n", err)
			os.Exit(1)
		}
		printResponse(resp)

	case "update":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Usage: %s update <zone>\n", os.Args[0])
			os.Exit(1)
		}
		zone := os.Args[3]
		msg := client.MakeUpdateQuery(zone, nil)
		resp, err := c.Query(msg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "UPDATE query error: %v\n", err)
			os.Exit(1)
		}
		printResponse(resp)

	case "opcode":
		if len(os.Args) < 5 {
			fmt.Fprintf(os.Stderr, "Usage: %s opcode <name> <type> <opcode>\n", os.Args[0])
			os.Exit(1)
		}
		name := os.Args[3]
		qtypeStr := os.Args[4]
		opcodeStr := os.Args[5]

		qtype := dns.TypeA
		var ok bool
		if qtypeStr != "" {
			qtype, ok = dns.StringToType[strings.ToUpper(qtypeStr)]
			if !ok {
				fmt.Fprintf(os.Stderr, "Unknown record type: %s\n", qtypeStr)
				os.Exit(1)
			}
		}

		opcode := uint8(0)
		fmt.Sscanf(opcodeStr, "%d", &opcode)

		msg := client.MakeQuery(name, qtype, opcode)
		resp, err := c.Query(msg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Opcode query error: %v\n", err)
			os.Exit(1)
		}
		printResponse(resp)

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		os.Exit(1)
	}
}

func formatFlags(hdr dns.MsgHeader) string {
	var flags []string
	if hdr.Response {
		flags = append(flags, "qr")
	}
	if hdr.Authoritative {
		flags = append(flags, "aa")
	}
	if hdr.Truncated {
		flags = append(flags, "tc")
	}
	if hdr.RecursionDesired {
		flags = append(flags, "rd")
	}
	if hdr.RecursionAvailable {
		flags = append(flags, "ra")
	}
	if hdr.Zero {
		flags = append(flags, "z")
	}
	if hdr.AuthenticatedData {
		flags = append(flags, "ad")
	}
	if hdr.CheckingDisabled {
		flags = append(flags, "cd")
	}
	return strings.Join(flags, ", ")
}

func printResponse(resp *dns.Msg) {
	fmt.Printf(";; Message ID: %d\n", resp.ID)
	fmt.Printf(";; Opcode: %d (%s)\n", resp.Opcode, dns.OpcodeToString[resp.Opcode])
	fmt.Printf(";; Rcode: %d (%s)\n", resp.Rcode, dns.RcodeToString[resp.Rcode])
	fmt.Printf(";; Flags: %s\n", formatFlags(resp.MsgHeader))

	fmt.Printf(";; Questions: %d\n", len(resp.Question))
	for _, q := range resp.Question {
		fmt.Printf(";;   %s\n", q.String())
	}
	fmt.Printf(";; Answers: %d\n", len(resp.Answer))
	for _, a := range resp.Answer {
		fmt.Printf(";;   %s\n", a.String())
	}
	fmt.Printf(";; Authority: %d\n", len(resp.Ns))
	for _, a := range resp.Ns {
		fmt.Printf(";;   %s\n", a.String())
	}
	fmt.Printf(";; Additional: %d\n", len(resp.Extra))
	for _, a := range resp.Extra {
		fmt.Printf(";;   %s\n", a.String())
	}
}
