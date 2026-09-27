package easyp2p

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type mqttLifecyclePublishStub struct {
	mqttSubscribeStub
	mu    sync.Mutex
	times []time.Time
	pub   func(string, string, int) mqtt.Token
}

func (c *mqttLifecyclePublishStub) Publish(topic string, qos byte, retained bool, payload interface{}) mqtt.Token {
	if qos != 1 || retained {
		panic("publish wire parameters changed")
	}
	c.mu.Lock()
	c.times = append(c.times, time.Now())
	call := len(c.times)
	c.mu.Unlock()
	return c.pub(topic, payload.(string), call)
}

func (c *mqttLifecyclePublishStub) callTimes() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Time(nil), c.times...)
}

func newMQTTLifecycleTestSession(t *testing.T, clients ...*mqttLifecyclePublishStub) (*MQTTSignalSession, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	// Leave the session alive on success: synctest must observe all exchange
	// workers exiting without session cancellation or a broker confirmation.
	t.Cleanup(func() {
		if t.Failed() {
			cancel()
		}
	})
	s, _ := newStalledSubscribeSession(ctx)
	s.cancel = cancel
	s.clients = nil
	for i, client := range clients {
		client.token = mqttCompletedTestToken(nil)
		s.clients = append(s.clients, mqttSignalClient{client: client, index: i})
	}
	return s, cancel
}

func TestMQTTMutualCompletionDoesNotWaitForSupplementaryPublish(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stalled := &mqttTestToken{done: make(chan struct{})}
		fast := &mqttLifecyclePublishStub{}
		slow := &mqttLifecyclePublishStub{pub: func(string, string, int) mqtt.Token { return stalled }}
		s, _ := newMQTTLifecycleTestSession(t, fast, slow)
		fast.pub = func(topic, _ string, call int) mqtt.Token {
			if call == 1 {
				s.dispatchMessage(topic, 0, "peer")
				return mqttCompletedTestToken(nil)
			}
			return stalled
		}
		started := time.Now()
		got, _, keepAlive, err := s.exchange(context.Background(), EXMODE_mutual, "self", "address", "session", time.Second, nil, mqttNoPreferredBroker)
		if err != nil || got != "peer" || !keepAlive {
			t.Fatalf("exchange = %q, %v, %v", got, keepAlive, err)
		}
		if elapsed := time.Since(started); elapsed != 0 {
			t.Fatalf("exchange waited %s for supplementary confirmation", elapsed)
		}
		synctest.Wait()
		if calls := len(fast.callTimes()); calls != 2 {
			t.Fatalf("publish calls = %d, want initial and immediate supplementary", calls)
		}
		time.Sleep(300 * time.Millisecond)
		synctest.Wait()
		if calls := len(fast.callTimes()); calls != 3 {
			t.Fatalf("publish calls = %d, want background burst after exchange returned", calls)
		}
		time.Sleep(mqttPublishKeepAlive)
		synctest.Wait()
		if len(fast.callTimes()) != 3 || s.ctx.Err() != nil {
			t.Fatal("unexpected further publish or session cancellation")
		}
		// The never-completed tokens must not leave workers alive in this bubble.
	})
}

func TestMQTTReplyBackgroundConfirmationWaitEndsAtKeepAlive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stalled := &mqttTestToken{done: make(chan struct{})}
		client := &mqttLifecyclePublishStub{pub: func(_ string, _ string, call int) mqtt.Token {
			if call == 1 {
				return mqttCompletedTestToken(nil)
			}
			return stalled
		}}
		s, _ := newMQTTLifecycleTestSession(t, client)
		_, _, keepAlive, err := s.exchange(context.Background(), exmodePublishOnly, "ACK", "hello", "session", time.Second, nil, 0)
		if err != nil || !keepAlive {
			t.Fatalf("reply = %v, %v", keepAlive, err)
		}
		time.Sleep(mqttPublishKeepAlive + time.Second)
		synctest.Wait()
		if calls := len(client.callTimes()); calls != 2 {
			t.Fatalf("publish calls = %d, want initial and stalled first burst", calls)
		}
		if s.ctx.Err() != nil {
			t.Fatal("reply stopped the session")
		}
	})
}

func TestMQTTExchangeFailureCancelsBackgroundConfirmationWait(t *testing.T) {
	for _, reason := range []string{"timeout", "caller", "handler", "session"} {
		t.Run(reason, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				stalled := &mqttTestToken{done: make(chan struct{})}
				client := &mqttLifecyclePublishStub{pub: func(_ string, _ string, call int) mqtt.Token {
					if call == 1 {
						return mqttCompletedTestToken(nil)
					}
					return stalled
				}}
				s, _ := newMQTTLifecycleTestSession(t, client)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				handlerErr := errors.New("invalid peer message")
				time.AfterFunc(300*time.Millisecond, func() {
					switch reason {
					case "caller":
						cancel()
					case "handler":
						s.dispatchMessage(topicFromSaltAndSessionUid("address", "session"), 0, "peer")
					case "session":
						s.Close()
					}
				})
				_, _, keepAlive, err := s.exchange(ctx, EXMODE_mutual, "self", "address", "session", 750*time.Millisecond,
					func(string) (bool, error) { return false, handlerErr }, mqttNoPreferredBroker)
				if err == nil || keepAlive {
					t.Fatalf("exchange = %v, %v", keepAlive, err)
				}
				if reason == "handler" && !errors.Is(err, handlerErr) {
					t.Fatalf("handler error = %v", err)
				}
				if reason == "timeout" && !strings.Contains(err.Error(), "timeout waiting") {
					t.Fatalf("timeout error = %v", err)
				}
				time.Sleep(mqttPublishKeepAlive + time.Second)
				synctest.Wait()
				if calls := len(client.callTimes()); calls != 2 {
					t.Fatalf("publish calls = %d, want initial and stalled first burst", calls)
				}
				if reason != "session" && s.ctx.Err() != nil {
					t.Fatal("exchange failure canceled the session")
				}
			})
		})
	}
}

func TestMQTTBackgroundScopesAreIndependentAndKeepBurstTiming(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &mqttLifecyclePublishStub{}
		s, _ := newMQTTLifecycleTestSession(t, client)
		var mu sync.Mutex
		var successfulPublishes []time.Time
		client.pub = func(topic, payload string, _ int) mqtt.Token {
			if payload == "successful" {
				mu.Lock()
				successfulPublishes = append(successfulPublishes, time.Now())
				mu.Unlock()
				s.dispatchMessage(topic, 0, "peer")
			}
			return mqttCompletedTestToken(nil)
		}
		started := time.Now()
		_, _, _, err := s.exchange(context.Background(), EXMODE_mutual, "successful", "address", "session", time.Second, nil, mqttNoPreferredBroker)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, err = s.exchange(context.Background(), EXMODE_mutual, "failed", "sync", "session", 500*time.Millisecond, nil, mqttNoPreferredBroker)
		if err == nil {
			t.Fatal("second exchange did not time out")
		}
		time.Sleep(2600 * time.Millisecond)
		synctest.Wait()
		mu.Lock()
		times := append([]time.Time(nil), successfulPublishes...)
		mu.Unlock()
		want := []time.Duration{0, 0, 200 * time.Millisecond, time.Second, 3 * time.Second}
		if len(times) != len(want) {
			t.Fatalf("successful exchange publishes = %d, want %d", len(times), len(want))
		}
		for i, at := range times {
			if got := at.Sub(started); got != want[i] {
				t.Fatalf("publish %d at %s, want %s", i, got, want[i])
			}
		}
		time.Sleep(3 * time.Second)
		synctest.Wait()
		before := len(client.callTimes())
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if len(client.callTimes()) != before || s.ctx.Err() != nil {
			t.Fatal("publishing continued after keep-alive or canceled shared session")
		}
	})
}

func TestMQTTSessionCloseStopsSuccessfulExchangeBackground(t *testing.T) {
	for _, mode := range []int{EXMODE_mutual, exmodePublishOnly} {
		synctest.Test(t, func(t *testing.T) {
			client := &mqttLifecyclePublishStub{}
			s, _ := newMQTTLifecycleTestSession(t, client)
			stalled := &mqttTestToken{done: make(chan struct{})}
			client.pub = func(topic, _ string, call int) mqtt.Token {
				if call == 1 {
					if mode == EXMODE_mutual {
						s.dispatchMessage(topic, 0, "peer")
					}
					return mqttCompletedTestToken(nil)
				}
				return stalled
			}
			_, _, keepAlive, err := s.exchange(context.Background(), mode, "self", "address", "session", time.Second, nil, 0)
			if err != nil || !keepAlive {
				t.Fatalf("mode %d: exchange = %v, %v", mode, keepAlive, err)
			}
			time.Sleep(300 * time.Millisecond)
			synctest.Wait()
			before := len(client.callTimes())
			s.Close()
			synctest.Wait()
			time.Sleep(mqttPublishKeepAlive + time.Second)
			synctest.Wait()
			if len(client.callTimes()) != before {
				t.Fatal("publish started after session closed")
			}
		})
	}
}
