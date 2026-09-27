package easyp2p

import (
	"fmt"
	"strings"
	"sync"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type mqttPublishDiagnosticAttempt struct {
	token mqtt.Token // Nil until Publish returns; not evidence of a network write.
}

type mqttBrokerPublishDiagnostic struct {
	attempts, returned, confirmed, failed int
	lastError                             error
	pending                               map[*mqttPublishDiagnosticAttempt]struct{}
}

type mqttPublishDiagnostics struct {
	mu      sync.Mutex
	brokers map[int]*mqttBrokerPublishDiagnostic
}

// Observe the actual token, not the result of a context-bounded wait. A caller
// timeout does not mean the broker rejected the publish or that it was unsent.
func (b *mqttBrokerPublishDiagnostic) collect() {
	for attempt := range b.pending {
		if attempt.token == nil {
			continue
		}
		select {
		case <-attempt.token.Done():
			if err := attempt.token.Error(); err != nil {
				b.failed++
				b.lastError = err
			} else {
				b.confirmed++
			}
			delete(b.pending, attempt)
		default:
		}
	}
}

func (d *mqttPublishDiagnostics) publish(client mqttSignalClient, topic string, qos byte, payload string) mqtt.Token {
	d.mu.Lock()
	if d.brokers == nil {
		d.brokers = make(map[int]*mqttBrokerPublishDiagnostic)
	}
	b := d.brokers[client.index]
	if b == nil {
		b = &mqttBrokerPublishDiagnostic{pending: make(map[*mqttPublishDiagnosticAttempt]struct{})}
		d.brokers[client.index] = b
	}
	b.collect()
	attempt := &mqttPublishDiagnosticAttempt{}
	b.attempts++
	b.pending[attempt] = struct{}{}
	d.mu.Unlock()

	token := client.client.Publish(topic, qos, false, payload)
	d.mu.Lock()
	attempt.token = token
	b.returned++
	d.mu.Unlock()
	return token
}

func (d *mqttPublishDiagnostics) summary(s *MQTTSignalSession) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	details := make([]string, 0, len(s.brokers))
	for index := range s.brokers {
		b := d.brokers[index]
		if b == nil {
			details = append(details, s.brokerName(index)+": not attempted")
			continue
		}
		b.collect()
		calling, pending := 0, 0
		for attempt := range b.pending {
			if attempt.token == nil {
				calling++
			} else {
				pending++
			}
		}
		status := fmt.Sprintf("%s: attempts=%d publish_returned=%d calling=%d token_pending=%d confirmed=%d failed=%d", s.brokerName(index), b.attempts, b.returned, calling, pending, b.confirmed, b.failed)
		if b.lastError != nil {
			status += fmt.Sprintf(" last_error=%q", b.lastError)
		}
		details = append(details, status)
	}
	return "publish=[" + strings.Join(details, "; ") + "]"
}

type mqttReceiveDiagnostics struct {
	mu                                 sync.Mutex
	self, filtered, handlerErrors      int
	valid, enqueued, firstQueuedBroker int
}

func (w *mqttSignalWaiter) receiveSummary(s *MQTTSignalSession) string {
	w.diagnostics.mu.Lock()
	defer w.diagnostics.mu.Unlock()
	d := &w.diagnostics
	status := fmt.Sprintf("receive=[valid=%d enqueued=%d buffered=%d self=%d filtered=%d handler_errors=%d", d.valid, d.enqueued, len(w.recvCh), d.self, d.filtered, d.handlerErrors)
	if d.enqueued > 0 {
		status += "; first_enqueued_via=" + s.brokerName(d.firstQueuedBroker)
	}
	return status + "]"
}
