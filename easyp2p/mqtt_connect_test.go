package easyp2p

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/eclipse/paho.mqtt.golang/packets"
)

type mqttConnectCleanupStub struct {
	mqttSubscribeStub
	quiesce []uint
}

func (c *mqttConnectCleanupStub) Disconnect(quiesce uint) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.quiesce = append(c.quiesce, quiesce)
	c.disconnected = true
}

func newMQTTConnectTestSession(parent context.Context) (*MQTTSignalSession, []*mqttConnectCleanupStub) {
	ctx, cancel := context.WithCancel(parent)
	s, _ := newStalledSubscribeSession(ctx)
	s.cancel = cancel
	s.clients = nil
	s.brokers = []string{"tcp://user:secret@first.example:1883", "tcp://second.example:1883"}
	clients := []*mqttConnectCleanupStub{{}, {}}
	for _, client := range clients {
		s.allClients = append(s.allClients, client)
	}
	return s, clients
}

func TestMQTTInitialConnectionOverallTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, clients := newMQTTConnectTestSession(context.Background())
		defer s.Close()
		s.failures = map[mqttSignalFailureKey]*mqttSignalFailure{
			{broker: 0}: {lastErr: errors.New("lookup first.example: i/o timeout")},
		}
		started := time.Now()
		err := s.waitForFirstConnection(make(chan struct{}), make(chan struct{}))
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) != 15*time.Second {
			t.Fatalf("elapsed=%s err=%v", time.Since(started), err)
		}
		for _, want := range []string{"MQTT initial connection failed after 15s", "first.example: last connection error: lookup", "second.example: connection not confirmed"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("missing %q in %v", want, err)
			}
		}
		if strings.Contains(err.Error(), "secret") || !s.closed || s.ctx.Err() == nil {
			t.Fatal("credentials exposed or failed session not closed")
		}
		for _, c := range clients {
			if len(c.quiesce) != 1 || c.quiesce[0] != 0 {
				t.Fatalf("timeout cleanup must not add per-broker delays: %v", c.quiesce)
			}
		}
		// A late OnConnect must not resurrect a failed session.
		s.brokerConnected(clients[0], 0)
		if len(s.clientsSnapshot()) != 0 {
			t.Fatal("late connection resurrected closed session")
		}
	})
}

func TestMQTTInitialConnectionSuccessDoesNotExpireSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, clients := newMQTTConnectTestSession(context.Background())
		defer s.Close()
		ready := make(chan struct{}, 1)
		time.AfterFunc(2*time.Second, func() {
			s.brokerConnected(clients[0], 0)
			ready <- struct{}{}
		})
		started := time.Now()
		if err := s.waitForFirstConnection(ready, make(chan struct{})); err != nil {
			t.Fatal(err)
		}
		if time.Since(started) != 2*time.Second {
			t.Fatal("first success did not return immediately")
		}
		time.Sleep(20 * time.Second)
		s.brokerConnected(clients[1], 1)
		if s.ctx.Err() != nil || s.closed || len(s.clientsSnapshot()) != 2 {
			t.Fatal("initial deadline expired the session or prevented later brokers joining")
		}
	})
}

func TestMQTTInitialConnectionHonorsParentAndTerminalFailures(t *testing.T) {
	for _, scenario := range []string{"deadline", "canceled", "all-failed"} {
		t.Run(scenario, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				parent := context.Background()
				want := errors.New("caller stopped")
				elapsed := time.Duration(0)
				if scenario == "deadline" {
					var cancel context.CancelFunc
					parent, cancel = context.WithTimeout(parent, 3*time.Second)
					defer cancel()
					want, elapsed = context.DeadlineExceeded, 3*time.Second
				} else if scenario == "canceled" {
					var cancel context.CancelCauseFunc
					parent, cancel = context.WithCancelCause(parent)
					cancel(want)
				}
				s, _ := newMQTTConnectTestSession(parent)
				defer s.Close()
				ready, fail := make(chan struct{}, 1), make(chan struct{}, 2)
				if scenario == "all-failed" {
					fail <- struct{}{}
					fail <- struct{}{}
				} else if scenario == "canceled" {
					ready <- struct{}{} // Cancellation takes precedence over a stale notification.
				}
				started := time.Now()
				err := s.waitForFirstConnection(ready, fail)
				if err == nil || time.Since(started) != elapsed || !s.closed {
					t.Fatalf("elapsed=%s closed=%v err=%v", time.Since(started), s.closed, err)
				}
				if scenario != "all-failed" && !errors.Is(err, want) {
					t.Fatalf("error=%v, want cause %v", err, want)
				}
			})
		})
	}
}

func TestMQTTInitialConnectionCancellationClosesLateHandshake(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s, err := newMQTTSignalSession(ctx, []string{"tcp://" + listener.Addr().String()}, "startup-cancel-test", "", io.Discard)
		if s != nil {
			s.Close()
		}
		result <- err
	}()
	defer wg.Wait()
	defer cancel()
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if packet, err := packets.ReadPacket(conn); err != nil {
		t.Fatal(err)
	} else if _, ok := packet.(*packets.ConnectPacket); !ok {
		t.Fatalf("unexpected packet %T", packet)
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("startup error=%v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("startup remained blocked in MQTT handshake")
	}
	// Complete the broker side after startup has already failed. The client
	// must close it, not retain a connection or begin reconnecting.
	ack := packets.NewControlPacket(packets.Connack).(*packets.ConnackPacket)
	if err := ack.Write(conn); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				t.Fatal("late MQTT connection was not closed")
			}
			break
		}
	}
}
