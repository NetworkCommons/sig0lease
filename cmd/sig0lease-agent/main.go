// Package main implements sig0lease-agent: the long-running client that keeps what a template
// describes registered: hosts and services through SRP registrars, names and their records
// through the sig0lease proxy's RFC 9664 handler (client/agent). See docs/sig0lease-agent.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/NetworkCommons/sig0lease/client/agent"
	"github.com/NetworkCommons/sig0lease/client/mdnsbridge"
	"github.com/NetworkCommons/sig0lease/logging"
	_ "github.com/NetworkCommons/sig0lease/pkg/dnscompat" // registers EDNS0 code 2 (UPDATE-LEASE), as every command does
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "validate":
		err = withTemplate(args, validate)
	case "plan":
		err = withTemplate(args, plan)
	case "run":
		err = runCommand(args)
	case "mdns-list":
		err = withTemplate(args, mdnsList)
	case "types":
		if len(args) != 0 {
			err = errors.New("types takes no arguments")
		} else {
			types()
		}
	case "help", "-h", "-help", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "ERROR: unknown command %q\n\n", cmd)
		printUsage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}

// withTemplate runs f on the one template args names, once it is valid.
func withTemplate(args []string, f func(path string, p *agent.Plan) error) error {
	if len(args) != 1 {
		return errors.New("give exactly one template file")
	}
	p, err := agent.Load(args[0])
	if err != nil {
		return err
	}
	return f(args[0], p)
}

func validate(path string, p *agent.Plan) error {
	var hosts, services, mirrors, names int
	for _, r := range p.Registrars {
		hosts, mirrors, names = hosts+len(r.Hosts), mirrors+len(r.Mirrors), names+len(r.Names)
		for _, h := range r.Hosts {
			services += len(h.Services)
		}
	}
	fmt.Printf("%s is valid: %d registrar(s); %d host(s), %d service(s), %d mirror(s); %d name(s)\n", path, len(p.Registrars), hosts, services, mirrors, names)
	return nil
}

func plan(_ string, p *agent.Plan) error {
	return agent.Describe(os.Stdout, p, nil, logging.NewLogger("info"))
}

func logf(format string, args ...any) {
	fmt.Printf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
}

func runCommand(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	poll := fs.Duration("poll-interval", 10*time.Second, "how often the template and this machine's addresses are read again")
	probe := fs.Duration("probe-interval", 30*time.Second, "how often each probed service is probed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *poll <= 0 || *probe <= 0 {
		return fmt.Errorf("-poll-interval and -probe-interval must be above zero (got %s and %s)", *poll, *probe)
	}
	opts := agent.Options{Logf: logf, PollInterval: *poll, ProbeInterval: *probe}
	return withTemplate(fs.Args(), func(path string, _ *agent.Plan) error {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		logf("sig0lease-agent: running %s; Ctrl-C or SIGTERM deregisters everything and stops", path)
		if err := agent.Run(ctx, path, opts); err != nil && ctx.Err() == nil {
			return err
		}
		logf("stopped")
		return nil
	})
}

// mdnsList prints what the template's mdns mirror would see, registering nothing.
func mdnsList(_ string, p *agent.Plan) error {
	_, m, ok := p.Mirror("mdns")
	if !ok {
		return errors.New("the template has no mdns mirror")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	logf("what the daemon at %s sees; * marks what the mirror registers. Ctrl-C to stop.", m.Socket)
	err := mdnsbridge.Run(ctx, mdnsbridge.Config{
		Source:       mdnsbridge.DaemonSource(m.Socket),
		ServiceTypes: m.ServiceTypes,
		Hosts:        m.Hosts,
		AllHosts:     m.AllHosts,
		List:         true,
		Logf:         logf,
	})
	if err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

func types() {
	fmt.Println("Presets: data types a service names with type:, overriding any field it gives itself")
	for _, t := range agent.Types() {
		if !t.Complex {
			fmt.Printf("  %-14s %s\n", t.Name, t.Summary)
		}
	}
	fmt.Println("\nComplex types: code, not data; a template uses them but cannot define them")
	for _, t := range agent.Types() {
		if t.Complex {
			fmt.Printf("  %-14s %s\n", t.Name, t.Summary)
		}
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `sig0lease-agent - keeps a template's hosts and services registered through SRP
registrars (RFC 9665), and its names and their records through the sig0lease proxy (RFC 9664)

Usage:
  sig0lease-agent validate <template.yaml>   check the template; exit 1 listing every problem
  sig0lease-agent plan <template.yaml>       validate, then show what run would register,
                                             changing nothing
  sig0lease-agent run [-poll-interval=10s] [-probe-interval=30s] <template.yaml>
                                             validate, then register and keep registered until
                                             Ctrl-C or SIGTERM, which deregister everything; the
                                             template is read again every -poll-interval, and
                                             each probed service probed every -probe-interval
  sig0lease-agent types                      list the preset and complex types
  sig0lease-agent mdns-list <template.yaml>  show what the mDNS daemon sees, * marking what the
                                             template's mdns mirror registers; registers nothing

The keystore is the template's keystore:, or else the CLIENT_KEYSTORE_DIR
environment variable; one of the two is required. The template format, the presets, probes
and the state the agent keeps are described in docs/sig0lease-agent.md.
`)
}
