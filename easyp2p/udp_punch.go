package easyp2p

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Diagnostics are collected silently and appended only to traversal failures.
// Send counts measure local writes, not delivery to the peer.
type udpPunchStats struct {
	mu                        sync.Mutex
	active, exits, readErrors int
	sent, failed, bindFailed  int
	first                     error
}

func (s *udpPunchStats) noteSend(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.sent++
	} else {
		s.failed++
		if s.first == nil {
			s.first = err
		}
	}
}

func (s *udpPunchStats) noteBindError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bindFailed++
	if s.first == nil {
		s.first = err
	}
}

func (s *udpPunchStats) summary() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	first := "none"
	if s.first != nil {
		first = s.first.Error()
	}
	return fmt.Sprintf("sent=%d; failed=%d; bind_failed=%d; receivers=%d; read_exits=%d; read_errors=%d; first_error=%q", s.sent, s.failed, s.bindFailed, s.active, s.exits, s.readErrors, first)
}

type udpPunchReceiver struct {
	active atomic.Bool
	stats  *udpPunchStats
	close  func()
}

const maxUDPPunchSourceReceivers = 900

// A round owns these receivers; batches only add candidates. Creation and
// eviction are serialized so even a new batch cannot exceed the socket cap.
type udpPunchReceiverPool struct {
	mu        sync.Mutex
	receivers []*udpPunchReceiver
	closed    bool
}

func (p *udpPunchReceiverPool) add(ctx context.Context, create func() (*udpPunchReceiver, error)) (*udpPunchReceiver, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.closed {
		return nil, context.Canceled
	}
	n := 0
	for _, r := range p.receivers {
		if r.active.Load() {
			p.receivers[n] = r
			n++
		}
	}
	clear(p.receivers[n:])
	p.receivers = p.receivers[:n]
	if len(p.receivers) == maxUDPPunchSourceReceivers {
		p.receivers[0].finish()
		copy(p.receivers, p.receivers[1:])
		p.receivers[len(p.receivers)-1] = nil
		p.receivers = p.receivers[:len(p.receivers)-1]
	}
	r, err := create()
	if err != nil {
		return nil, err
	}
	p.receivers = append(p.receivers, r)
	return r, nil
}

// Stop new batches under the eviction lock before acknowledging a winning
// candidate. Round cancellation, not this stop, closes the retained sockets.
func (p *udpPunchReceiverPool) selectReceiver(ctx context.Context, r *udpPunchReceiver, stop context.CancelFunc) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || ctx.Err() != nil || !r.active.Load() {
		return false
	}
	stop()
	return true
}

func (p *udpPunchReceiverPool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for _, r := range p.receivers {
		r.finish()
	}
	p.receivers = nil
}

func newUDPPunchReceiver(stats *udpPunchStats, close func()) *udpPunchReceiver {
	r := &udpPunchReceiver{stats: stats, close: close}
	r.active.Store(true)
	stats.mu.Lock()
	stats.active++
	stats.mu.Unlock()
	return r
}

func (r *udpPunchReceiver) finish() {
	if !r.active.Swap(false) {
		return
	}
	r.stats.mu.Lock()
	r.stats.active--
	r.stats.mu.Unlock()
	if r.close != nil {
		r.close()
	}
}

func readUDPPunchPacket(ctx context.Context, receiver *udpPunchReceiver, read func([]byte) (int, error), buf []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	n, err := read(buf)
	if err == nil {
		return n, nil
	}
	// Expected cancellation and receive expiry are not abnormal read failures.
	if ctx.Err() != nil || !receiver.active.Load() {
		return 0, err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return 0, err
	}
	receiver.stats.mu.Lock()
	receiver.stats.readErrors++
	receiver.stats.exits++
	if receiver.stats.first == nil {
		receiver.stats.first = err
	}
	receiver.stats.mu.Unlock()
	receiver.finish()
	return 0, err
}
