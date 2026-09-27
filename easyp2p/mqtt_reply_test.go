package easyp2p

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type mqttReplyStub struct {
	mqttSubscribeStub
	pubMu    sync.Mutex
	pubCalls int
	pub      func(int) mqtt.Token
}

func (c *mqttReplyStub) Publish(_ string, qos byte, retained bool, payload interface{}) mqtt.Token {
	if qos != 1 || retained || payload != "ACK@test" {
		panic("reply wire parameters changed")
	}
	c.pubMu.Lock()
	c.pubCalls++
	call := c.pubCalls
	c.pubMu.Unlock()
	return c.pub(call)
}

func (c *mqttReplyStub) publishCalls() int {
	c.pubMu.Lock()
	defer c.pubMu.Unlock()
	return c.pubCalls
}

func mqttCompletedTestToken(err error) *mqttTestToken {
	token := &mqttTestToken{done: make(chan struct{}), err: err}
	close(token.done)
	return token
}

func newMQTTReplyTestSession(ctx context.Context, clients ...*mqttReplyStub) *MQTTSignalSession {
	s, _ := newStalledSubscribeSession(ctx)
	s.clients = nil
	s.brokers = []string{"tcp://preferred:1883", "tcp://other:1883", "tcp://late:1883"}
	for index, client := range clients {
		s.clients = append(s.clients, mqttSignalClient{client: client, index: index})
	}
	return s
}

func TestMQTTReplyAcceptsLateConfirmationAfterPeerReceivedACK(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	late := &mqttTestToken{done: make(chan struct{})}
	delivered := make(chan struct{}, 1)
	preferred := &mqttReplyStub{pub: func(int) mqtt.Token {
		delivered <- struct{}{}
		return late
	}}
	other := &mqttReplyStub{pub: func(int) mqtt.Token { return mqttCompletedTestToken(io.EOF) }}
	s := newMQTTReplyTestSession(ctx, preferred, other)
	result := make(chan error, 1)
	go func() {
		_, index, keepAlive, err := s.exchange(ctx, exmodePublishOnly, "ACK@test", "salt", "session", 3*time.Second, nil, 0)
		if err == nil && (index != 0 || !keepAlive) {
			err = errors.New("wrong successful broker or missing continuation")
		}
		result <- err
	}()
	select {
	case <-delivered:
	case <-ctx.Done():
		t.Fatal("ACK not delivered")
	}
	// The peer has the ACK, but the publisher receives PUBACK after both old
	// windows (800ms + 500ms) would have expired.
	select {
	case err := <-result:
		t.Fatalf("reply finished before confirmation: %v", err)
	case <-time.After(1500 * time.Millisecond):
	}
	if preferred.publishCalls() != 1 || other.publishCalls() != 1 {
		t.Fatal("pending request duplicated or another broker not attempted")
	}
	close(late.done)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestMQTTReplyOtherBrokerDoesNotWaitForPreferred(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stalled := &mqttTestToken{done: make(chan struct{})}
	preferred := &mqttReplyStub{pub: func(int) mqtt.Token { return stalled }}
	other := &mqttReplyStub{pub: func(int) mqtt.Token { return mqttCompletedTestToken(nil) }}
	s := newMQTTReplyTestSession(ctx, preferred, other)
	deadline, stop := context.WithTimeout(ctx, 400*time.Millisecond)
	defer stop()
	var output bytes.Buffer
	s.logger = log.New(&output, "[MQTT] ", 0)
	index, err := s.publishReply(deadline, "topic", 1, "ACK@test", 0)
	if err != nil || index != 1 {
		t.Fatalf("publishReply = %d, %v; want other broker immediately", index, err)
	}
	want := "[MQTT] ACK publish confirmed by broker other; SYN received via preferred; topic=topic\n"
	if got := output.String(); got != want {
		t.Fatalf("ACK diagnostic = %q, want %q", got, want)
	}
}

func TestMQTTReplyIncludesNewlyConnectedBroker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	called := make(chan struct{}, 1)
	preferred := &mqttReplyStub{pub: func(int) mqtt.Token {
		called <- struct{}{}
		return &mqttTestToken{done: make(chan struct{})}
	}}
	s := newMQTTReplyTestSession(ctx, preferred)
	result := make(chan error, 1)
	go func() {
		index, err := s.publishReply(ctx, "topic", 1, "ACK@test", 0)
		if err == nil && index != 2 {
			err = errors.New("wrong broker index")
		}
		result <- err
	}()
	select {
	case <-called:
	case <-ctx.Done():
		t.Fatal("initial publication not started")
	}
	s.brokerConnected(&mqttReplyStub{pub: func(int) mqtt.Token { return mqttCompletedTestToken(nil) }}, 2)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestMQTTReplyRetriesErrorsWithoutLosingPendingRequests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	stalled := &mqttReplyStub{pub: func(int) mqtt.Token { return &mqttTestToken{done: make(chan struct{})} }}
	retry := &mqttReplyStub{pub: func(call int) mqtt.Token {
		if call == 1 {
			return mqttCompletedTestToken(io.EOF)
		}
		return mqttCompletedTestToken(nil)
	}}
	s := newMQTTReplyTestSession(ctx, stalled, retry)
	index, err := s.publishReply(ctx, "topic", 1, "ACK@test", 0)
	if err != nil || index != 1 || stalled.publishCalls() != 1 || retry.publishCalls() != 2 {
		t.Fatalf("index=%d err=%v publish calls=%d/%d", index, err, stalled.publishCalls(), retry.publishCalls())
	}
}

func TestMQTTReplyFinalDiagnostic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	pending := &mqttReplyStub{pub: func(int) mqtt.Token { return &mqttTestToken{done: make(chan struct{})} }}
	failed := &mqttReplyStub{pub: func(int) mqtt.Token { return mqttCompletedTestToken(io.EOF) }}
	s := newMQTTReplyTestSession(context.Background(), pending, failed)
	var output bytes.Buffer
	s.logger = log.New(&output, "[MQTT] ", 0)
	_, err := s.publishReply(ctx, "topic", 1, "ACK@test", 0)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v", err)
	}
	for _, want := range []string{"unconfirmed after", "preferred: publish incomplete", "other: EOF", "late: not connected"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %q in %q", want, output.String())
		}
	}
	if strings.Count(output.String(), "\n") != 1 {
		t.Fatalf("expected one final diagnostic, got %q", output.String())
	}
}

func TestMQTTReplyStopsOnSessionCancellation(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	called := make(chan struct{}, 1)
	client := &mqttReplyStub{pub: func(int) mqtt.Token {
		called <- struct{}{}
		return &mqttTestToken{done: make(chan struct{})}
	}}
	s := newMQTTReplyTestSession(ctx, client)
	deadline, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	defer cancel(context.Canceled)
	result := make(chan error, 1)
	go func() { _, err := s.publishReply(deadline, "topic", 1, "ACK@test", 0); result <- err }()
	select {
	case <-called:
	case <-deadline.Done():
		t.Fatal("publication not started")
	}
	cause := errors.New("session closed")
	cancel(cause)
	if err := <-result; !errors.Is(err, cause) {
		t.Fatalf("error = %v, want session cancellation cause", err)
	}
}

func TestMQTTConnectionSuccessAndLossAreQuiet(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newMQTTReplyTestSession(ctx)
	var output bytes.Buffer
	s.logger = log.New(&output, "[MQTT] ", 0)
	client := &mqttReplyStub{}
	s.brokerConnected(client, 0)
	s.brokerConnectionLost(client, 0, errors.New("pingresp not received"))
	s.brokerConnected(client, 0)
	if output.Len() != 0 {
		t.Fatalf("unexpected extra logging: %q", output.String())
	}
	cancel()
	s.brokerConnectionLost(client, 0, io.EOF)
	if output.Len() != 0 {
		t.Fatal("intentional session cancellation logged as disconnection")
	}
}
