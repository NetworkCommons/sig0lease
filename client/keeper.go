package client

import (
	"context"
	"fmt"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
)

// KeeperConfig configures how one registration is kept as what it should register changes:
// client/srp's Host and client/rfc9664's Name.
type KeeperConfig struct {
	// Settle is how long changes are collected before the registration is sent again; default 1s.
	Settle time.Duration
	// StopTimeout bounds each withdrawal or deregistration sent outside the refresh clock;
	// default 10s.
	StopTimeout time.Duration
	// KeepNames makes deregistering, on Stop or when nothing is left to register, keep the
	// names reserved for the key until the KEY-LEASE ends, so that it gets them back when it
	// returns. Without it the names are freed.
	KeepNames bool
	// Logf receives the log lines, each starting with the name kept. Default: none.
	Logf func(format string, args ...any)
	// OnFatal is called, at most once, with an error no later change can cure: a client
	// configuration the protocol's NewClient refuses. Nothing more is registered until Stop.
	OnFatal func(error)
}

// Defaults applies the defaults of the fields left zero.
func (cfg *KeeperConfig) Defaults() {
	if cfg.Settle <= 0 {
		cfg.Settle = time.Second
	}
	if cfg.StopTimeout <= 0 {
		cfg.StopTimeout = 10 * time.Second
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.OnFatal == nil {
		cfg.OnFatal = func(error) {}
	}
}

// Moves are what a Keeper does, each called from its goroutine alone.
type Moves[S any] struct {
	// To moves to next, from what the previous call registered: it sends whatever withdraws
	// what next lacks, and returns the registration to keep (run until its ctx ends), nil for
	// none. An error is one no later state can cure: the Keeper reports it to OnFatal and
	// waits to be stopped.
	To func(next S) (keep func(context.Context), err error)
	// Kept, if set, is called once a registration To returned has stopped, before the next
	// To or Leave.
	Kept func()
	// Leave deregisters what To registered, as the Keeper stops. Its error goes to OnFatal.
	Leave func() error
}

// Keeper keeps one registration current as what it should register changes: it takes the
// states Set gives it, collects further ones until none comes for Settle, stops keeping the
// previous registration, and moves to the latest (Moves.To); Stop stops keeping it and leaves
// (Moves.Leave).
type Keeper[S any] struct {
	cfg     KeeperConfig
	moves   Moves[S]
	updates chan S
	quit    chan struct{}
	done    chan struct{}
	stop    sync.Once
}

// StartKeeper starts a Keeper. cfg must have its defaults (KeeperConfig.Defaults). It does
// nothing until the first Set.
func StartKeeper[S any](cfg KeeperConfig, moves Moves[S]) *Keeper[S] {
	k := &Keeper[S]{
		cfg:     cfg,
		moves:   moves,
		updates: make(chan S, 1),
		quit:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go k.run()
	return k
}

// Set replaces what should be registered with s, replacing any earlier Set the Keeper has not
// taken yet. It never blocks. Set must not be called from more than one goroutine at a time.
func (k *Keeper[S]) Set(s S) {
	select {
	case <-k.updates:
	default:
	}
	k.updates <- s
}

// Stop starts stopping the Keeper: it stops keeping the registration and leaves
// (Moves.Leave); Wait waits for it to finish. It may be called more than once.
func (k *Keeper[S]) Stop() { k.stop.Do(func() { close(k.quit) }) }

// Wait returns once the Keeper has stopped (Stop).
func (k *Keeper[S]) Wait() { <-k.done }

func (k *Keeper[S]) run() {
	defer close(k.done)
	var cancelKeep func()
	var keepDone chan struct{}
	stopKeeping := func() {
		if cancelKeep == nil {
			return
		}
		cancelKeep()
		<-keepDone
		cancelKeep = nil
		if k.moves.Kept != nil {
			k.moves.Kept()
		}
	}
	leave := func() {
		stopKeeping()
		if err := k.moves.Leave(); err != nil {
			k.cfg.OnFatal(err)
		}
	}

	for {
		var next S
		select {
		case next = <-k.updates:
		case <-k.quit:
			leave()
			return
		}
		// Collect further changes until none arrives for Settle.
		for settling := true; settling; {
			select {
			case next = <-k.updates:
			case <-time.After(k.cfg.Settle):
				settling = false
			case <-k.quit:
				leave()
				return
			}
		}
		stopKeeping()

		keep, err := k.moves.To(next)
		if err != nil {
			k.cfg.OnFatal(err)
			<-k.quit
			return
		}
		if keep != nil {
			ctx, cancel := context.WithCancel(context.Background())
			cancelKeep, keepDone = cancel, make(chan struct{})
			go func(done chan struct{}) {
				defer close(done)
				keep(ctx)
			}(keepDone)
		}
	}
}

// Report logs to logf how action went, done if it succeeded, and reports whether it did.
func Report(logf func(format string, args ...any), action, done string, outcome Outcome, err error) bool {
	switch {
	case err != nil:
		logf("%s: %v", action, err)
	case outcome != OutcomeSuccess:
		logf("%s: registrar answered %s", action, outcome)
	default:
		logf("%s", done)
		return true
	}
	return false
}

// DescribeAnswer describes a registrar's answer for an error: its outcome, RCODE and EDEs.
func DescribeAnswer(resp *dns.Msg, outcome Outcome) string {
	reason := fmt.Sprintf("%s (rcode=%d", outcome, resp.Rcode)
	for _, ede := range dnsmsg.EDEs(resp) {
		reason += ", EDE " + dnsmsg.FormatEDE(ede)
	}
	return reason + ")"
}
