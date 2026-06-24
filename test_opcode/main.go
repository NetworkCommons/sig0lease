package main

import (
	"fmt"
	"net"
	"codeberg.org/miekg/dns"
)

func main() {
	// Create a UDP server to test WriteTo with a real ResponseWriter
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		fmt.Printf("Listen error: %v\n", err)
		return
	}
	defer listener.Close()
	
	addr := listener.LocalAddr().(*net.UDPAddr)
	
	// Send a test UPDATE query
	req := new(dns.Msg)
	req.ID = 0x1234
	question := &dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET},
	}
	req.Question = []dns.RR{question}
	req.Opcode = 5
	req.Response = false
	
	// Pack the request
	err = req.Pack()
	if err != nil {
		fmt.Printf("Pack error: %v\n", err)
		return
	}
	
	// Send it
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		fmt.Printf("Dial error: %v\n", err)
		return
	}
	defer conn.Close()
	
	_, err = conn.Write(req.Data)
	if err != nil {
		fmt.Printf("Write error: %v\n", err)
		return
	}
	
	fmt.Println("Sent UPDATE query with Opcode=5")
	
	// Create a UDP server to handle the request and send response
	go func() {
		buf := make([]byte, 4096)
		n, clientAddr, err := listener.ReadFrom(buf)
		if err != nil {
			fmt.Printf("Read error: %v\n", err)
			return
		}
		
		fmt.Printf("\nReceived request from %s\n", clientAddr)
		
		var req dns.Msg
		err = req.Unpack()
		if err != nil {
			fmt.Printf("Unpack error: %v\n", err)
			return
		}
		
		fmt.Printf("Request Opcode=%d, Response=%v\n", req.Opcode, req.Response)
		
		// Create response
		resp := new(dns.Msg)
		resp.ID = req.ID
		resp.Opcode = 5
		resp.Response = true
		resp.Rcode = dns.RcodeSuccess
		
		question := &dns.SOA{
			Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET},
		}
		resp.Question = []dns.RR{question}
		
		fmt.Printf("\nCreating response: Opcode=%d, Response=%v\n", resp.Opcode, resp.Response)
		
		err = resp.Pack()
		if err != nil {
			fmt.Printf("Pack error: %v\n", err)
			return
		}
		
		fmt.Printf("Response Data after Pack: %02x\n", resp.Data[:12])
		
		// Write response
		n, err = conn.Write(resp.Data)
		fmt.Printf("Write response: n=%d, err=%v\n", n, err)
		
		// Verify by unpacking what we wrote
		if len(resp.Data) >= 12 {
			bits := uint16(resp.Data[2])<<8 | uint16(resp.Data[3])
			qr := (bits >> 15) & 0x1
			opcode := (bits >> 11) & 0xF
			fmt.Printf("Response header flags: QR=%d, OPCODE=%d\n", qr, opcode)
		}
	}()
	
	// Give time for goroutine to start
	fmt.Println("Server started, sending query...")
}
