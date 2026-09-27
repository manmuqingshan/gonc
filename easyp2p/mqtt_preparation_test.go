package easyp2p

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

func TestP2PNATCheckDoesNotWaitForAnySubscription(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s, _ := newStalledSubscribeSession(ctx)
	s.clients = s.clients[1:]
	output := &natProgressWriter{cancel: cancel}
	_, err := Easy_P2P_MPWithOptions(ctx, "udp4", "stalled-subscription", EasyP2PMPOptions{
		Signal: s, LogWriter: output,
	})
	if !errors.Is(err, context.Canceled) || !strings.Contains(output.String(), "Getting local public IP info") {
		t.Fatalf("STUN did not start before subscription completion: err=%v log=%q", err, output.String())
	}
	if s.subscribedCount(topicFromSaltAndSessionUid("gonc-exchange-address", "stalled-subscription")) != 0 {
		t.Fatal("unexpected successful subscription")
	}
}

func TestMQTTBackgroundPreparationSharesInflightExchangeSubscription(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		address := topicFromSaltAndSessionUid("gonc-exchange-address", "session")
		syncTopic := topicFromSaltAndSessionUid("gonc-exchange-sync", "session")
		token := &mqttTestToken{done: make(chan struct{})}
		client := &mqttRetrySubscribeStub{sub: func(topic string, _ int) mqtt.Token {
			if topic == address {
				return token
			}
			return mqttCompletedTestToken(nil)
		}}
		s, _ := newMQTTRetryTestSession(ctx, client)
		s.clients = s.clients[1:]
		client.publish = func(topic, _ string) { s.dispatchMessage(topic, 1, "peer") }
		started := time.Now()
		stop := s.prepareP2PTopicsInBackground(ctx, "session")
		defer stop()
		synctest.Wait()
		if time.Since(started) != 0 || client.callCount() != 1 {
			t.Fatal("preparation blocked or did not start the subscription")
		}
		// Simulate STUN completing while the address SUBACK is still pending.
		time.Sleep(2 * time.Second)
		result := make(chan error, 1)
		go func() {
			_, _, _, err := s.exchange(ctx, EXMODE_mutual, "self", "gonc-exchange-address", "session", 5*time.Second, nil, mqttNoPreferredBroker)
			result <- err
		}()
		synctest.Wait()
		if client.callCount() != 1 {
			t.Fatal("exchange duplicated the in-flight subscription")
		}
		select {
		case err := <-result:
			t.Fatalf("exchange did not wait for subscription: %v", err)
		default:
		}
		close(token.done)
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		stop()
		if client.callCount() != 2 || s.subscribedCount(address) != 1 || s.subscribedCount(syncTopic) != 1 {
			t.Fatal("preparation did not register both topics once")
		}
		if err := s.subscribe(ctx, syncTopic, 1); err != nil || client.callCount() != 2 || ctx.Err() != nil {
			t.Fatalf("stopping preparation invalidated reusable subscriptions: %v", err)
		}
	})
}

func TestMQTTBackgroundPreparationTimeoutDoesNotEndExchange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		client := &mqttRetrySubscribeStub{sub: func(_ string, call int) mqtt.Token {
			token := &mqttTestToken{done: make(chan struct{})}
			if call == 3 {
				// Retries start at 0, 11, 23 seconds. Confirmation at 28s
				// arrives after the 25s preparation budget has ended.
				time.AfterFunc(5*time.Second, func() { close(token.done) })
			}
			return token
		}}
		s, _ := newMQTTRetryTestSession(ctx, client)
		s.clients = s.clients[1:]
		client.publish = func(topic, _ string) { s.dispatchMessage(topic, 1, "peer") }
		started := time.Now()
		stop := s.prepareP2PTopicsInBackground(ctx, "session")
		defer stop()
		synctest.Wait()
		time.Sleep(26 * time.Second)
		synctest.Wait()
		stop()
		got, _, _, err := s.exchange(ctx, EXMODE_mutual, "self", "gonc-exchange-address", "session", 5*time.Second, nil, mqttNoPreferredBroker)
		if err != nil || got != "peer" || ctx.Err() != nil {
			t.Fatalf("exchange failed after preparation timed out: got=%q err=%v", got, err)
		}
		if time.Since(started) != 28*time.Second || client.callCount() != 3 {
			t.Fatal("exchange did not reuse the pending background retry")
		}
	})
}

func TestMQTTBackgroundPreparationStopReclaimsWaiter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		s, _ := newStalledSubscribeSession(ctx)
		s.clients = s.clients[1:]
		started := time.Now()
		stop := s.prepareP2PTopicsInBackground(ctx, "session")
		synctest.Wait()
		stop()
		if time.Since(started) != 0 || ctx.Err() != nil {
			t.Fatal("cleanup waited for SUBACK or canceled the shared session")
		}
	})
}
