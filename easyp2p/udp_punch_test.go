package easyp2p

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestUDPPunchReadErrorsReturnImmediatelyAndAreCounted(t *testing.T) {
	stats := &udpPunchStats{}
	failures := []error{
		syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.EINTR,
		syscall.EAGAIN, syscall.ENOBUFS, syscall.EHOSTUNREACH,
		os.ErrDeadlineExceeded, net.ErrClosed, syscall.EBADF,
		os.ErrPermission, errors.New("unknown read failure"),
		&net.OpError{Op: "read", Net: "udp", Err: syscall.ECONNREFUSED},
	}
	for _, want := range failures {
		calls, closes := 0, 0
		receiver := newUDPPunchReceiver(stats, func() { closes++ })
		_, err := readUDPPunchPacket(context.Background(), receiver, func([]byte) (int, error) {
			calls++
			return 0, want
		}, make([]byte, 32))
		if err != want || calls != 1 || receiver.active.Load() || closes != 1 {
			t.Fatalf("err=%v want=%v reads=%d active=%v closes=%d", err, want, calls, receiver.active.Load(), closes)
		}
		receiver.finish()
		if closes != 1 {
			t.Fatal("receiver closed twice")
		}
	}
	if stats.readErrors != len(failures) || stats.exits != len(failures) || stats.active != 0 || stats.first != failures[0] {
		t.Fatal(stats.summary())
	}
}

func TestUDPPunchReadSuccessKeepsReceiverActive(t *testing.T) {
	stats := &udpPunchStats{}
	receiver := newUDPPunchReceiver(stats, nil)
	defer receiver.finish()
	buf := make([]byte, 32)
	n, err := readUDPPunchPacket(context.Background(), receiver, func(buf []byte) (int, error) {
		return copy(buf, "punch"), nil
	}, buf)
	if err != nil || string(buf[:n]) != "punch" || !receiver.active.Load() || stats.readErrors != 0 || stats.exits != 0 {
		t.Fatalf("n=%d err=%v stats=%s", n, err, stats.summary())
	}
}

func TestUDPPunchNormalShutdownIsNotReadFailure(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		stats := &udpPunchStats{}
		receiver := newUDPPunchReceiver(stats, nil)
		ctx, cancel := context.WithCancel(context.Background())
		if deadline {
			cancel()
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		} else {
			cancel()
		}
		_, err := readUDPPunchPacket(ctx, receiver, func([]byte) (int, error) {
			t.Fatal("read after cancellation")
			return 0, nil
		}, make([]byte, 32))
		cancel()
		receiver.finish()
		if err == nil || !strings.Contains(stats.summary(), "read_exits=0; read_errors=0;") {
			t.Fatal(stats.summary())
		}
	}
}

func TestUDPPunchReadRealClosedSocketRetiresReceiver(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	stats := &udpPunchStats{}
	receiver := newUDPPunchReceiver(stats, func() { conn.Close() })
	conn.Close()
	_, err = readUDPPunchPacket(context.Background(), receiver, conn.Read, make([]byte, 32))
	if !errors.Is(err, net.ErrClosed) || receiver.active.Load() || stats.exits != 1 {
		t.Fatalf("err=%v active=%v stats=%s", err, receiver.active.Load(), stats.summary())
	}
}

func TestUDPPunchSocketDeadlineIsNormal(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	stats := &udpPunchStats{}
	receiver := newUDPPunchReceiver(stats, func() { conn.Close() })
	defer receiver.finish()
	deadline := time.Now().Add(50 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	_, err = readUDPPunchPacket(ctx, receiver, conn.Read, make([]byte, 32))
	if err == nil || stats.readErrors != 0 || stats.exits != 0 {
		t.Fatalf("normal batch deadline treated as failure: %v; %s", err, stats.summary())
	}
}

func TestUDPPunchFailureCounters(t *testing.T) {
	stats := &udpPunchStats{}
	stats.noteSend(nil)
	stats.noteSend(syscall.ENETUNREACH)
	stats.noteBindError(os.ErrPermission)
	if !strings.Contains(stats.summary(), "sent=1; failed=1; bind_failed=1;") || stats.first != syscall.ENETUNREACH {
		t.Fatal(stats.summary())
	}
}

func TestUDPPunchFailureReturnsDiagnosticsWithoutExtraLogs(t *testing.T) {
	t.Setenv("ROLE_DEBUG", "S")
	local, remote := reserveUDPAddrPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	logs := &udpPunchTestLog{batches: make(chan string, 1)}
	conn, _, _, err := Auto_P2P_UDP_NAT_Traversal(ctx, "udp4", "failure-diagnostics", loopbackUDPP2PInfo(local, remote), &P2PSessionContext{}, 0, nil, logs)
	if conn != nil {
		conn.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v", err)
	}
	for _, field := range []string{"P2P UDP hole punching failed:", "sent=", "failed=", "bind_failed=", "receivers=", "read_exits=0", "read_errors=0", "first_error="} {
		if !strings.Contains(err.Error(), field) {
			t.Fatalf("missing %q in %v", field, err)
		}
	}
	logs.mu.Lock()
	defer logs.mu.Unlock()
	if strings.Contains(logs.text.String(), "read_errors=") || strings.Contains(logs.text.String(), "first_error=") {
		t.Fatalf("diagnostics logged separately: %s", logs.text.String())
	}
}

type udpPunchTestLog struct {
	mu      sync.Mutex
	text    strings.Builder
	batches chan string
}

func (l *udpPunchTestLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	l.text.Write(p)
	l.mu.Unlock()
	if strings.Contains(string(p), "Random Src Ports") {
		select {
		case l.batches <- string(p):
		default:
		}
	}
	return len(p), nil
}

func TestUDPPunchRetainsEarlierBatchAndPreservesLogs(t *testing.T) {
	for _, role := range []string{"C", "S"} {
		t.Run(role, func(t *testing.T) { testUDPPunchRetainsEarlierBatch(t, role) })
	}
}

func testUDPPunchRetainsEarlierBatch(t *testing.T, role string) {
	t.Setenv("ROLE_DEBUG", role)
	oldCount, oldTTL := PunchingRandomPortCount, PunchingShortTTL
	PunchingRandomPortCount, PunchingShortTTL = 2, 5
	t.Cleanup(func() { PunchingRandomPortCount, PunchingShortTTL = oldCount, oldTTL })
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	local, _ := reserveUDPAddrPair(t)
	info := loopbackUDPP2PInfo(local, peer.LocalAddr().String())
	info.LocalNAT, info.LocalNATType = "198.51.100.1:12345", "symm"
	packets := make(chan *net.UDPAddr, 32)
	go func() {
		buf := make([]byte, 64)
		for {
			_, addr, err := peer.ReadFromUDP(buf)
			if err != nil {
				return
			}
			select {
			case packets <- addr:
			default:
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result := make(chan traversalResult, 1)
	logs := &udpPunchTestLog{batches: make(chan string, 4)}
	go runUDPTraversal(ctx, info, logs, result)
	consumed := false
	defer func() {
		cancel()
		if !consumed {
			select {
			case got := <-result:
				if got.conn != nil {
					got.conn.Close()
				}
			case <-time.After(2 * time.Second):
				t.Error("traversal failed to stop")
			}
		}
	}()
	readBatch := func(ttl string) map[int]*net.UDPAddr {
		t.Helper()
		select {
		case line := <-logs.batches:
			if !strings.Contains(line, "TTL="+ttl+"; total=2\n") {
				t.Fatalf("log format/TTL changed: %s", line)
			}
		case <-ctx.Done():
			t.Fatal("missing batch")
		}
		ports := make(map[int]*net.UDPAddr)
		for len(ports) < 2 {
			select {
			case addr := <-packets:
				if addr.String() != local {
					ports[addr.Port] = addr
				}
			case <-ctx.Done():
				t.Fatal("missing packets")
			}
		}
		return ports
	}
	firstTTL, secondTTL := "7", "9"
	if role == "S" {
		firstTTL, secondTTL = "64", "64"
	}
	first := readBatch(firstTTL)
	// The old five-second receive deadline must no longer release these ports.
	time.Sleep(5500 * time.Millisecond)
	for _, addr := range first {
		guard, err := net.ListenUDP("udp4", addr)
		if err == nil {
			guard.Close()
			t.Fatal("source socket closed before the round ended")
		}
	}
	second := readBatch(secondTTL)
	for port := range second {
		if first[port] != nil {
			t.Fatal("old socket reused")
		}
	}
	// Respond only to an earlier batch after the new batch has started.
	var selected *net.UDPAddr
	for _, addr := range first {
		selected = addr
		if _, err := peer.WriteToUDP([]byte(deriveKeyForPayload("udp-context-test", true)), addr); err != nil {
			t.Fatal(err)
		}
		break
	}
	select {
	case got := <-result:
		consumed = true
		if got.err != nil || got.conn == nil {
			t.Fatalf("retained first batch failed: %v", got.err)
		}
		defer got.conn.Close()
		if got.conn.LocalAddr().String() != selected.String() {
			t.Fatalf("selected %s, want earlier port %s", got.conn.LocalAddr(), selected)
		}
		for _, batch := range []map[int]*net.UDPAddr{first, second} {
			for _, addr := range batch {
				if addr.Port == selected.Port {
					continue
				}
				guard, err := net.ListenUDP("udp4", addr)
				if err != nil {
					t.Fatalf("unused source socket leaked after success: %v", err)
				}
				guard.Close()
			}
		}
		// Pool cleanup must not close the replacement business connection.
		if _, err := peer.WriteToUDP([]byte("business-data"), selected); err != nil {
			t.Fatal(err)
		}
		got.conn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 64)
		n, err := got.conn.Read(buf)
		if err != nil || string(buf[:n]) != "business-data" {
			t.Fatalf("connection handoff: %q, %v", buf[:n], err)
		}
	case <-ctx.Done():
		t.Fatal("retained source port did not establish connection")
	}
	logs.mu.Lock()
	output := logs.text.String()
	logs.mu.Unlock()
	for _, field := range []string{"fixed=", "refresh=", "receivers=", "read_errors=", "first_error="} {
		if strings.Contains(output, field) {
			t.Fatalf("diagnostics leaked into normal logs: %s", output)
		}
	}
}

func TestUDPPunchReceiverPoolCapsAt900AndEvictsOldest(t *testing.T) {
	pool := &udpPunchReceiverPool{}
	defer pool.close()
	stats := &udpPunchStats{}
	var receivers []*udpPunchReceiver
	closed := make([]int, 1100)
	open, peak := 0, 0
	for i := range closed {
		r, err := pool.add(context.Background(), func() (*udpPunchReceiver, error) {
			open++
			if open > peak {
				peak = open
			}
			return newUDPPunchReceiver(stats, func() { open--; closed[i]++ }), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		receivers = append(receivers, r)
	}
	if open != 900 || peak != 900 || stats.active != 900 || len(pool.receivers) != 900 {
		t.Fatalf("open=%d peak=%d pool=%d stats=%s", open, peak, len(pool.receivers), stats.summary())
	}
	for i, r := range receivers {
		if r.active.Load() != (i >= 200) {
			t.Fatalf("candidate %d has incorrect eviction state", i)
		}
	}
	pool.close()
	pool.close()
	for i, count := range closed {
		if count != 1 {
			t.Fatalf("candidate %d closed %d times", i, count)
		}
	}
	if open != 0 || stats.active != 0 || stats.readErrors != 0 {
		t.Fatal(stats.summary())
	}
}

func TestUDPPunchReceiverPoolReusesFailedSlotsAndProtectsWinner(t *testing.T) {
	pool := &udpPunchReceiverPool{}
	defer pool.close()
	stats := &udpPunchStats{}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	create := func() (*udpPunchReceiver, error) { return newUDPPunchReceiver(stats, nil), nil }
	var receivers []*udpPunchReceiver
	for range 900 {
		r, err := pool.add(ctx, create)
		if err != nil {
			t.Fatal(err)
		}
		receivers = append(receivers, r)
	}
	readErr := errors.New("read failed")
	_, err := readUDPPunchPacket(ctx, receivers[500], func([]byte) (int, error) { return 0, readErr }, nil)
	if err != readErr {
		t.Fatal(err)
	}
	if _, err := pool.add(ctx, create); err != nil {
		t.Fatal(err)
	}
	if !receivers[0].active.Load() || receivers[500].active.Load() || stats.active != 900 {
		t.Fatalf("valid oldest receiver evicted instead of using failed slot: %s", stats.summary())
	}
	if pool.selectReceiver(ctx, receivers[500], stop) || ctx.Err() != nil {
		t.Fatal("failed receiver selected")
	}
	if !pool.selectReceiver(ctx, receivers[0], stop) {
		t.Fatal("valid winner rejected")
	}
	_, err = pool.add(ctx, func() (*udpPunchReceiver, error) {
		t.Fatal("created a new socket after selecting the winner")
		return nil, nil
	})
	if !errors.Is(err, context.Canceled) || !receivers[0].active.Load() {
		t.Fatal("winner closed before its acknowledgement completed")
	}
	pool.close()
	_, err = pool.add(context.Background(), create)
	if !errors.Is(err, context.Canceled) || stats.active != 0 || stats.readErrors != 1 {
		t.Fatalf("err=%v stats=%s", err, stats.summary())
	}
}

func TestUDPPunchReceiverPoolEvictionUnblocksReadWithoutErrorCount(t *testing.T) {
	pool := &udpPunchReceiverPool{}
	defer pool.close()
	stats := &udpPunchStats{}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	r, err := pool.add(context.Background(), func() (*udpPunchReceiver, error) {
		return newUDPPunchReceiver(stats, func() { conn.Close() }), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readUDPPunchPacket(context.Background(), r, conn.Read, make([]byte, 32))
		done <- err
	}()
	for range 900 {
		if _, err := pool.add(context.Background(), func() (*udpPunchReceiver, error) {
			return newUDPPunchReceiver(stats, nil), nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("evicted read error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("evicted receiver is still reading")
	}
	if stats.readErrors != 0 || stats.exits != 0 {
		t.Fatal(stats.summary())
	}
}

func TestUDPPunchRetainedSocketsCloseOnCancellation(t *testing.T) {
	for _, reason := range []string{"cancel", "deadline"} {
		t.Run(reason, func(t *testing.T) { testUDPPunchRetainedSocketsClose(t, reason) })
	}
}

func testUDPPunchRetainedSocketsClose(t *testing.T, reason string) {
	t.Setenv("ROLE_DEBUG", "C")
	oldCount := PunchingRandomPortCount
	PunchingRandomPortCount = 2
	t.Cleanup(func() { PunchingRandomPortCount = oldCount })
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	local, _ := reserveUDPAddrPair(t)
	info := loopbackUDPP2PInfo(local, peer.LocalAddr().String())
	info.LocalNAT, info.LocalNATType = "198.51.100.1:12345", "symm"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan traversalResult, 1)
	go runUDPTraversal(ctx, info, &udpPunchTestLog{}, result)
	peer.SetReadDeadline(time.Now().Add(6 * time.Second))
	ports := make(map[int]*net.UDPAddr)
	for len(ports) < 2 {
		_, addr, err := peer.ReadFromUDP(make([]byte, 64))
		if err != nil {
			t.Fatal(err)
		}
		if addr.String() != local {
			ports[addr.Port] = addr
		}
	}
	wantErr := context.DeadlineExceeded
	if reason == "cancel" {
		cancel()
		wantErr = context.Canceled
	}
	select {
	case got := <-result:
		if got.conn != nil {
			got.conn.Close()
		}
		if !errors.Is(got.err, wantErr) {
			t.Fatalf("traversal error = %v", got.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("traversal did not stop")
	}
	for _, addr := range ports {
		guard, err := net.ListenUDP("udp4", addr)
		if err != nil {
			t.Fatalf("retained socket leaked on cancellation: %v", err)
		}
		guard.Close()
	}
}
