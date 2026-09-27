package easyp2p

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

func requireMQTTDiagnostic(t *testing.T, got string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %q", want, got)
		}
	}
}

func TestMQTTReplyDiagnosticDistinguishesPublishCallAndToken(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		defer close(release)
		calling := &mqttReplyStub{pub: func(int) mqtt.Token {
			<-release
			return mqttCompletedTestToken(nil)
		}}
		pending := &mqttReplyStub{pub: func(int) mqtt.Token { return &mqttTestToken{done: make(chan struct{})} }}
		failed := &mqttReplyStub{pub: func(int) mqtt.Token { return mqttCompletedTestToken(io.EOF) }}
		s := newMQTTReplyTestSession(context.Background(), calling, pending, failed)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := s.publishReply(ctx, "topic", 1, "ACK@test", 0)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v", err)
		}
		requireMQTTDiagnostic(t, err.Error(),
			"preferred: attempts=1 publish_returned=0 calling=1 token_pending=0 confirmed=0 failed=0",
			"other: attempts=1 publish_returned=1 calling=0 token_pending=1 confirmed=0 failed=0",
			"late: attempts=1 publish_returned=1 calling=0 token_pending=0 confirmed=0 failed=1 last_error=\"EOF\"")
		if calling.publishCalls() != 1 || pending.publishCalls() != 1 || failed.publishCalls() != 1 {
			t.Fatal("diagnostic changed publish attempts")
		}
	})
}

func TestMQTTExchangeFailurePublishDiagnostics(t *testing.T) {
	for _, initiallyConfirmed := range []bool{false, true} {
		name := "initial-publish-pending"
		if initiallyConfirmed {
			name = "background-publish-pending"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client := &mqttLifecyclePublishStub{pub: func(_, _ string, call int) mqtt.Token {
					if initiallyConfirmed && call == 1 {
						return mqttCompletedTestToken(nil)
					}
					return &mqttTestToken{done: make(chan struct{})}
				}}
				s, cancel := newMQTTLifecycleTestSession(t, client)
				defer cancel()
				_, _, _, err := s.exchange(context.Background(), EXMODE_mutual, "self", "address", "session", time.Second, nil, mqttNoPreferredBroker)
				if err == nil {
					t.Fatal("expected exchange timeout")
				}
				requireMQTTDiagnostic(t, err.Error(), "MQTT exchange", "receive=[valid=0 enqueued=0 buffered=0", "not attempted")
				if initiallyConfirmed {
					requireMQTTDiagnostic(t, err.Error(), "initial_publish_wait=0s", "attempts=2 publish_returned=2 calling=0 token_pending=1 confirmed=1 failed=0")
				} else {
					requireMQTTDiagnostic(t, err.Error(), "initial_publish_wait=1s", "attempts=1 publish_returned=1 calling=0 token_pending=1 confirmed=0 failed=0")
				}
			})
		})
	}
}

func TestMQTTReceiveDiagnosticDoesNotConsumeMessages(t *testing.T) {
	s := newMQTTReplyTestSession(context.Background())
	w := &mqttSignalWaiter{
		selfPayload: "self",
		recvCh:      make(chan mqttSignalRecvPayload, 1),
		errCh:       make(chan error, 1),
		handler: func(data string) (bool, error) {
			if data == "invalid" {
				return false, errors.New("invalid message")
			}
			return data == "ACK", nil
		},
	}
	// Exercise the existing pre-waiter cache as well as live delivery.
	s.dispatchMessage("topic", 1, "ACK")
	remove := s.addWaiter("topic", w)
	defer remove()
	for _, data := range []string{"self", "filtered", "invalid", "ACK"} {
		s.dispatchMessage("topic", 0, data)
	}
	for range 2 {
		requireMQTTDiagnostic(t, w.receiveSummary(s), "valid=2 enqueued=1 buffered=1 self=1 filtered=1 handler_errors=1", "first_enqueued_via=other")
	}
	if msg := <-w.recvCh; msg.data != "ACK" || msg.index != 1 {
		t.Fatalf("queued message changed: %+v", msg)
	}
	requireMQTTDiagnostic(t, w.receiveSummary(s), "valid=2 enqueued=1 buffered=0")
	if len(w.errCh) != 1 {
		t.Fatal("diagnostic consumed the handler error")
	}
}

func TestMQTTPublishDiagnosticObservesTokenAfterWaitCancellation(t *testing.T) {
	d := &mqttPublishDiagnostics{}
	token := &mqttTestToken{done: make(chan struct{})}
	c := &mqttReplyStub{pub: func(int) mqtt.Token { return token }}
	s := newMQTTReplyTestSession(context.Background(), c)
	got := d.publish(s.clients[0], "topic", 1, "ACK@test")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitMQTTTokenContext(ctx, got); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait error = %v", err)
	}
	requireMQTTDiagnostic(t, d.summary(s), "token_pending=1 confirmed=0 failed=0")
	close(token.done)
	for range 2 {
		requireMQTTDiagnostic(t, d.summary(s), "token_pending=0 confirmed=1 failed=0")
	}
}

func TestMQTTReceiveDiagnosticWhileInitialPublishWaits(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &mqttLifecyclePublishStub{}
		s, cancel := newMQTTLifecycleTestSession(t, client)
		defer cancel()
		client.pub = func(topic, _ string, call int) mqtt.Token {
			if call == 1 {
				s.dispatchMessage(topic, 0, "ACK")
			}
			return &mqttTestToken{done: make(chan struct{})}
		}
		result := make(chan error, 1)
		started := time.Now()
		go func() {
			_, _, _, err := s.exchange(context.Background(), EXMODE_mutual, "SYN", "hello", "session", time.Second, nil, mqttNoPreferredBroker)
			result <- err
		}()
		synctest.Wait()
		select {
		case <-result:
			t.Fatal("diagnostics changed initial publish waiting behavior")
		default:
		}
		topic := topicFromSaltAndSessionUid("hello", "session")
		s.mu.Lock()
		var waiter *mqttSignalWaiter
		for w := range s.waiters[topic] {
			waiter = w
		}
		s.mu.Unlock()
		if waiter == nil {
			t.Fatal("waiter not registered")
		}
		requireMQTTDiagnostic(t, waiter.receiveSummary(s), "valid=1 enqueued=1 buffered=1", "first_enqueued_via=")
		// Preserve the existing select semantics when both the deadline and the
		// queued reply become eligible after the initial publish wait returns.
		if err := <-result; err != nil {
			requireMQTTDiagnostic(t, err.Error(), "initial_publish_wait=1s", "valid=1 enqueued=1 buffered=1")
		}
		if elapsed := time.Since(started); elapsed != time.Second {
			t.Fatalf("initial wait changed: %s", elapsed)
		}
	})
}
