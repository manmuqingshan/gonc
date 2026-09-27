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

type mqttTestToken struct {
	done chan struct{}
	err  error
}

func TestMQTTBrokerNameOnlyDisplaysHost(t *testing.T) {
	for _, tc := range []struct{ address, want string }{
		{"tcp://guest:guest@mqtt.gonc.cc:1883", "mqtt.gonc.cc"},
		{"tls://user:secret@broker.example:8883?insecure=1", "broker.example"},
		{"wss://user:secret@broker.example:443/mqtt?token=secret", "broker.example"},
		{"tcp://192.0.2.1:1883", "192.0.2.1"},
		{"tcp://user:secret@[2001:db8::1]:1883", "2001:db8::1"},
		{"broker.example:1883", "broker.example"},
		{"healthy", "healthy"},
		{"tcp://user:secret@broker.example:bad", "broker#0"},
		{"", "broker#0"},
	} {
		s := &MQTTSignalSession{brokers: []string{tc.address}}
		if got := s.brokerName(0); got != tc.want {
			t.Errorf("brokerName(%q) = %q, want %q", tc.address, got, tc.want)
		}
		if s.brokers[0] != tc.address {
			t.Fatal("display formatting changed connection configuration")
		}
	}
	s := &MQTTSignalSession{}
	for _, index := range []int{-1, 0} {
		if got := s.brokerName(index); !strings.HasPrefix(got, "broker#") {
			t.Errorf("invalid broker index %d: %q", index, got)
		}
	}
}

func (t *mqttTestToken) Wait() bool {
	<-t.done
	return true
}

func (t *mqttTestToken) WaitTimeout(timeout time.Duration) bool {
	select {
	case <-t.done:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (t *mqttTestToken) Done() <-chan struct{} { return t.done }
func (t *mqttTestToken) Error() error          { return t.err }

type mqttSubscribeStub struct {
	mqtt.Client
	mu           sync.Mutex
	token        mqtt.Token
	called       chan struct{}
	calls        int
	handler      mqtt.MessageHandler
	publish      func(string, string)
	disconnected bool
}

func (c *mqttSubscribeStub) IsConnectionOpen() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.disconnected
}

func (c *mqttSubscribeStub) Subscribe(_ string, _ byte, handler mqtt.MessageHandler) mqtt.Token {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.handler = handler
	if c.called != nil {
		select {
		case c.called <- struct{}{}:
		default:
		}
	}
	return c.token
}

func (c *mqttSubscribeStub) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (c *mqttSubscribeStub) Publish(topic string, _ byte, _ bool, payload interface{}) mqtt.Token {
	if c.publish != nil {
		c.publish(topic, payload.(string))
	}
	token := &mqttTestToken{done: make(chan struct{})}
	close(token.done)
	return token
}

type natProgressWriter struct {
	bytes.Buffer
	cancel context.CancelFunc
}

func (w *natProgressWriter) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	if strings.Contains(string(p), "Getting local public IP info") {
		w.cancel()
	}
	return n, err
}

func newStalledSubscribeSession(ctx context.Context) (*MQTTSignalSession, <-chan struct{}) {
	readyToken := &mqttTestToken{done: make(chan struct{})}
	close(readyToken.done)
	stalledToken := &mqttTestToken{done: make(chan struct{})}
	stalledCalled := make(chan struct{}, 1)
	return &MQTTSignalSession{
		ctx:           ctx,
		brokers:       []string{"healthy", "stalled"},
		clients:       []mqttSignalClient{{client: &mqttSubscribeStub{token: readyToken}, index: 0}, {client: &mqttSubscribeStub{token: stalledToken, called: stalledCalled}, index: 1}},
		logger:        log.New(io.Discard, "", 0),
		subscriptions: make(map[string]byte),
		subscribed:    make(map[string]map[int]struct{}),
		loggedSubs:    make(map[string]struct{}),
		waiters:       make(map[string]map[*mqttSignalWaiter]struct{}),
	}, stalledCalled
}

func TestP2PNATCheckProceedsAfterHealthySubscription(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	session, _ := newStalledSubscribeSession(ctx)
	// Put the stalled broker first to catch accidental serial waiting.
	session.clients[0], session.clients[1] = session.clients[1], session.clients[0]
	output := &natProgressWriter{cancel: cancel}
	_, err := Easy_P2P_MPWithOptions(ctx, "udp4", "slow-subscribe-repro", EasyP2PMPOptions{
		Signal: session, LogWriter: output,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("NAT check error = %v, want cancellation on reaching STUN", err)
	}
	if !strings.Contains(output.String(), "=== Checking NAT reachability ===") || !strings.Contains(output.String(), "Getting local public IP info") {
		t.Fatalf("unexpected NAT check progress: %q", output.String())
	}
}

func TestMQTTSubscribeSucceedsDespiteStalledBroker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	session, _ := newStalledSubscribeSession(ctx)
	const topic = "nat-exchange/slow-subscribe-repro"
	if err := session.subscribe(ctx, topic, 1); err != nil {
		t.Fatalf("subscribe error = %v", err)
	}
	if got := session.subscribedCount(topic); got != 1 {
		t.Fatalf("healthy broker subscriptions = %d, want 1", got)
	}
}

func TestMQTTExchangeReusesPreparedSubscription(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	session, _ := newStalledSubscribeSession(ctx)
	session.clients = session.clients[:1]
	client := session.clients[0].client.(*mqttSubscribeStub)
	if err := session.prepareTopic(ctx, "address", "session"); err != nil {
		t.Fatal(err)
	}
	topic := topicFromSaltAndSessionUid("address", "session")
	session.dispatchMessage(topic, 0, "peer-address")
	got, _, _, err := session.exchange(ctx, EXMODE_waitOnly, "", "address", "session", time.Second, nil, mqttNoPreferredBroker)
	if err != nil || got != "peer-address" {
		t.Fatalf("exchange = %q, %v", got, err)
	}
	if calls := client.callCount(); calls != 1 {
		t.Fatalf("Subscribe calls = %d, want one across prepare and exchange", calls)
	}
}

func TestMQTTSubscribeSharesInflightRequestAfterCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session, called := newStalledSubscribeSession(ctx)
	session.clients = session.clients[1:]
	client := session.clients[0].client.(*mqttSubscribeStub)
	firstCtx, cancelFirst := context.WithCancel(ctx)
	result := make(chan error, 1)
	go func() { result <- session.subscribe(firstCtx, "topic", 1) }()
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("Subscribe not started")
	}
	cancelFirst()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("first caller error = %v", err)
	}
	// Caller cancellation must not cancel the session-owned request.
	session.mu.Lock()
	attempt := session.subscribing["topic"][1]
	session.mu.Unlock()
	secondCtx, cancelSecond := context.WithTimeout(ctx, time.Second)
	defer cancelSecond()
	go func() { result <- session.subscribe(secondCtx, "topic", 1) }()
	close(client.token.(*mqttTestToken).done)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	session.mu.Lock()
	same := session.subscribing["topic"][1] == attempt
	session.mu.Unlock()
	if !same || client.callCount() != 1 {
		t.Fatal("in-flight subscription was replaced")
	}
}

func TestMQTTBackgroundSubscriptionCompletesAfterFirstSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	session, called := newStalledSubscribeSession(ctx)
	client := session.clients[1].client.(*mqttSubscribeStub)
	callerCtx, cancelCaller := context.WithCancel(ctx)
	if err := session.subscribe(callerCtx, "topic", 1); err != nil {
		t.Fatal(err)
	}
	cancelCaller()
	select {
	case <-called:
	case <-ctx.Done():
		t.Fatal("second broker subscription not started")
	}
	close(client.token.(*mqttTestToken).done)
	waitMQTTTestCondition(t, func() bool { return session.subscribedCount("topic") == 2 })
	if err := session.subscribe(ctx, "topic", 1); err != nil {
		t.Fatal(err)
	}
	if client.callCount() != 1 {
		t.Fatal("background subscription was not reused")
	}
}

func waitMQTTTestCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.After(time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !condition() {
		select {
		case <-deadline:
			t.Fatal("MQTT condition not reached")
		case <-tick.C:
		}
	}
}

type mqttTestMessage struct {
	mqtt.Message
	topic, payload string
}

func (m mqttTestMessage) Topic() string   { return m.topic }
func (m mqttTestMessage) Payload() []byte { return []byte(m.payload) }

func TestMQTTLateBrokerDeliversToActiveExchange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	session, _ := newStalledSubscribeSession(ctx)
	session.clients = session.clients[:1]
	topic := topicFromSaltAndSessionUid("address", "session")
	result := make(chan error, 1)
	go func() {
		got, index, _, err := session.exchange(ctx, EXMODE_waitOnly, "", "address", "session", time.Second, nil, mqttNoPreferredBroker)
		if err == nil && (got != "late-peer" || index != 1) {
			err = errors.New("wrong message or broker")
		}
		result <- err
	}()
	waitMQTTTestCondition(t, func() bool {
		session.mu.Lock()
		defer session.mu.Unlock()
		return len(session.waiters[topic]) == 1
	})
	token := &mqttTestToken{done: make(chan struct{})}
	close(token.done)
	late := &mqttSubscribeStub{token: token}
	session.brokerConnected(late, 1)
	waitMQTTTestCondition(t, func() bool { return session.subscribedCount(topic) == 2 })
	late.mu.Lock()
	handler := late.handler
	late.mu.Unlock()
	handler(late, mqttTestMessage{topic: topic, payload: "late-peer"})
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestMQTTMutualExchangeSucceedsWhenSubscriptionsOverlapLater(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	a, _ := newStalledSubscribeSession(ctx)
	b, _ := newStalledSubscribeSession(ctx)
	commonA := a.clients[1].client.(*mqttSubscribeStub)
	commonB := b.clients[1].client.(*mqttSubscribeStub)
	firstA := make(chan struct{}, 1)
	firstB := make(chan struct{}, 1)
	// The first broker on each side is private to that side. Only the
	// delayed common broker can carry messages to the other peer.
	route := func(peer *mqttSubscribeStub, sent chan struct{}) func(string, string) {
		return func(topic, payload string) {
			select {
			case sent <- struct{}{}:
			default:
			}
			peer.mu.Lock()
			token, handler := peer.token, peer.handler
			peer.mu.Unlock()
			select {
			case <-token.Done():
				if handler != nil {
					handler(peer, mqttTestMessage{topic: topic, payload: payload})
				}
			default:
			}
		}
	}
	commonA.publish = route(commonB, firstA)
	commonB.publish = route(commonA, firstB)
	for _, session := range []*MQTTSignalSession{a, b} {
		if err := session.prepareTopic(ctx, "address", "session"); err != nil {
			t.Fatal(err)
		}
	}
	result := make(chan error, 2)
	for i, session := range []*MQTTSignalSession{a, b} {
		send, want := "A", "B"
		if i == 1 {
			send, want = want, send
		}
		go func() {
			got, _, _, err := session.exchange(ctx, EXMODE_mutual, send, "address", "session", 2*time.Second, nil, mqttNoPreferredBroker)
			if err == nil && got != want {
				err = errors.New("received wrong peer payload")
			}
			result <- err
		}()
	}
	for _, sent := range []chan struct{}{firstA, firstB} {
		select {
		case <-sent:
		case <-ctx.Done():
			t.Fatal("initial publication did not start")
		}
	}
	select {
	case err := <-result:
		t.Fatalf("exchange finished before subscriptions overlapped: %v", err)
	default:
	}
	close(commonA.token.(*mqttTestToken).done)
	close(commonB.token.(*mqttTestToken).done)
	for range 2 {
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	}
	if commonA.callCount() != 1 || commonB.callCount() != 1 {
		t.Fatal("exchange repeated an in-flight background subscription")
	}
}

func TestMQTTReconnectRequiresNewSubscription(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	session, _ := newStalledSubscribeSession(ctx)
	session.clients = session.clients[:1]
	client := session.clients[0].client.(*mqttSubscribeStub)
	if err := session.subscribe(ctx, "topic", 1); err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	client.disconnected = true
	client.mu.Unlock()
	session.brokerConnectionLost(client, 0, io.EOF)
	if session.subscribedCount("topic") != 0 {
		t.Fatal("lost connection retained its subscription")
	}
	next := &mqttTestToken{done: make(chan struct{})}
	client.mu.Lock()
	client.token = next
	client.disconnected = false
	client.mu.Unlock()
	session.brokerConnected(client, 0)
	waitMQTTTestCondition(t, func() bool { return client.callCount() == 2 })
	if session.subscribedCount("topic") != 0 {
		t.Fatal("reconnected broker marked subscribed before SUBACK")
	}
	close(next.done)
	if err := session.subscribe(ctx, "topic", 1); err != nil {
		t.Fatal(err)
	}
	if client.callCount() != 2 || len(session.clientsSnapshot()) != 1 {
		t.Fatal("reconnect duplicated client or subscription")
	}
}

func TestMQTTStaleSubscriptionCannotMarkReconnectedBrokerReady(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session, _ := newStalledSubscribeSession(ctx)
	old := &mqttSubscriptionAttempt{cancel: func() {}}
	current := &mqttSubscriptionAttempt{cancel: func() {}}
	session.subscribing = map[string]map[int]*mqttSubscriptionAttempt{"topic": {0: current}}
	// Complete an old connection's request after a new request replaced it.
	session.runSubscription(ctx, session.clients[0].client, 0, "topic", 1, old)
	if session.subscribedCount("topic") != 0 || current.done {
		t.Fatal("stale completion changed current subscription state")
	}
}

func TestMQTTSubscriptionFailureCanRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	session, _ := newStalledSubscribeSession(ctx)
	session.clients = session.clients[:1]
	client := session.clients[0].client.(*mqttSubscribeStub)
	failed := &mqttTestToken{done: make(chan struct{}), err: errors.New("rejected")}
	close(failed.done)
	client.token = failed
	firstCtx, cancelFirst := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancelFirst()
	if err := session.subscribe(firstCtx, "topic", 1); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("all failed subscriptions returned success")
	}
	ready := &mqttTestToken{done: make(chan struct{})}
	close(ready.done)
	client.mu.Lock()
	client.token = ready
	client.mu.Unlock()
	if err := session.subscribe(ctx, "topic", 1); err != nil {
		t.Fatal(err)
	}
	if client.callCount() != 2 {
		t.Fatal("failed subscription was not retried")
	}
}

type mqttRejectedSubscribeToken struct{ *mqttTestToken }

func (t *mqttRejectedSubscribeToken) Result() map[string]byte {
	return map[string]byte{"topic": 0x80}
}

func TestMQTTRejectedSUBACKIsNotCached(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	session, _ := newStalledSubscribeSession(ctx)
	session.clients = session.clients[:1]
	client := session.clients[0].client.(*mqttSubscribeStub)
	client.token = &mqttRejectedSubscribeToken{client.token.(*mqttTestToken)}
	if err := session.subscribe(ctx, "topic", 1); err == nil {
		t.Fatal("rejected SUBACK returned success")
	}
	if session.subscribedCount("topic") != 0 {
		t.Fatal("rejected subscription was cached")
	}
}

func TestMQTTDelayedConnectionLostCallbackResubscribes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	session, _ := newStalledSubscribeSession(ctx)
	session.clients = session.clients[:1]
	client := session.clients[0].client.(*mqttSubscribeStub)
	if err := session.subscribe(ctx, "topic", 1); err != nil {
		t.Fatal(err)
	}
	// The connection is already open again when the old loss callback runs.
	session.brokerConnectionLost(client, 0, io.EOF)
	if err := session.subscribe(ctx, "topic", 1); err != nil {
		t.Fatal(err)
	}
	if client.callCount() != 2 || session.subscribedCount("topic") != 1 {
		t.Fatal("late loss callback left the reconnected broker unsubscribed")
	}
}

func TestMQTTSignalSessionReplaysMessageReceivedBeforeWaiter(t *testing.T) {
	const topic = "nat-exchange/test"

	session := &MQTTSignalSession{
		waiters: make(map[string]map[*mqttSignalWaiter]struct{}),
	}
	session.dispatchMessage(topic, 2, "remote-payload")

	waiter := &mqttSignalWaiter{
		selfPayload: "local-payload",
		handler: func(data string) (bool, error) {
			return data == "remote-payload", nil
		},
		recvCh: make(chan mqttSignalRecvPayload, 1),
		errCh:  make(chan error, 1),
	}
	remove := session.addWaiter(topic, waiter)
	defer remove()

	select {
	case got := <-waiter.recvCh:
		if got.data != "remote-payload" || got.index != 2 {
			t.Fatalf("cached MQTT payload = %+v, want data remote-payload from broker 2", got)
		}
	case err := <-waiter.errCh:
		t.Fatalf("cached MQTT payload returned handler error: %v", err)
	case <-time.After(time.Second):
		t.Fatal("cached MQTT payload was not replayed to waiter")
	}
}

func TestMQTTSignalSessionKeepsOnlyLatestMessageBeforeWaiter(t *testing.T) {
	const topic = "nat-exchange/test"

	session := &MQTTSignalSession{
		waiters: make(map[string]map[*mqttSignalWaiter]struct{}),
	}
	session.dispatchMessage(topic, 1, "older-payload")
	session.dispatchMessage(topic, 3, "latest-payload")

	waiter := &mqttSignalWaiter{
		recvCh: make(chan mqttSignalRecvPayload, 1),
		errCh:  make(chan error, 1),
	}
	remove := session.addWaiter(topic, waiter)
	defer remove()

	select {
	case got := <-waiter.recvCh:
		if got.data != "latest-payload" || got.index != 3 {
			t.Fatalf("cached MQTT payload = %+v, want latest-payload from broker 3", got)
		}
	case err := <-waiter.errCh:
		t.Fatalf("cached MQTT payload returned handler error: %v", err)
	case <-time.After(time.Second):
		t.Fatal("latest cached MQTT payload was not replayed to waiter")
	}
}

func TestMQTTSignalSessionCloseHasNoFixedDelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	session := &MQTTSignalSession{
		ctx:    ctx,
		cancel: cancel,
	}

	startedAt := time.Now()
	session.Close()
	if elapsed := time.Since(startedAt); elapsed >= 100*time.Millisecond {
		t.Fatalf("MQTTSignalSession.Close took %s, want less than 100ms", elapsed)
	}
}

func TestWaitMQTTTokenContextReturnsCancellationCause(t *testing.T) {
	cancelCause := errors.New("LAN path won")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(cancelCause)
	token := &mqttTestToken{done: make(chan struct{})}

	if err := waitMQTTTokenContext(ctx, token); !errors.Is(err, cancelCause) {
		t.Fatalf("waitMQTTTokenContext error = %v, want %v", err, cancelCause)
	}
}

func TestWaitMQTTTokenContextReturnsTokenError(t *testing.T) {
	tokenErr := errors.New("broker rejected request")
	token := &mqttTestToken{done: make(chan struct{}), err: tokenErr}
	close(token.done)

	if err := waitMQTTTokenContext(context.Background(), token); !errors.Is(err, tokenErr) {
		t.Fatalf("waitMQTTTokenContext error = %v, want %v", err, tokenErr)
	}
}

func TestMQTTTimeoutDiagnosticDistinguishesSubscriptionFromExchange(t *testing.T) {
	for _, stage := range []string{"subscription", "exchange"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s, _ := newStalledSubscribeSession(ctx)
			if stage == "subscription" {
				s.clients = s.clients[1:]
			} else {
				s.clients = s.clients[:1]
			}
			_, _, _, err := s.exchange(ctx, EXMODE_waitOnly, "", "hello", "session", 30*time.Millisecond, nil, mqttNoPreferredBroker)
			if err == nil || !strings.HasPrefix(err.Error(), "MQTT "+stage+" for topic ") {
				t.Fatalf("stage %s: %v", stage, err)
			}
			if stage == "subscription" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("subscription deadline cause lost: %v", err)
			}
			if stage == "exchange" && !strings.Contains(err.Error(), "timeout waiting for remote data exchange") {
				t.Fatalf("exchange timeout description lost: %v", err)
			}
		})
	}
}
