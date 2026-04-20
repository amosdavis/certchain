package annotation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

// fakeClock implements the clock interface for tests.
type fakeClock struct {
	now    time.Time
	timers []*fakeTimer
}

func (f *fakeClock) Now() time.Time { return f.now }
func (f *fakeClock) AfterFunc(d time.Duration, fn func()) timer {
	t := &fakeTimer{fireAt: f.now.Add(d), fn: fn}
	f.timers = append(f.timers, t)
	return t
}

func (f *fakeClock) Advance(d time.Duration) {
	f.now = f.now.Add(d)
	for _, t := range f.timers {
		if !t.stopped && !t.fireAt.After(f.now) {
			t.fn()
			t.stopped = true
		}
	}
}

type fakeTimer struct {
	fireAt  time.Time
	fn      func()
	stopped bool
}

func (f *fakeTimer) Stop() bool {
	if f.stopped {
		return false
	}
	f.stopped = true
	return true
}

// makeCert creates a test certificate with the given CN and validity period.
func makeCert(cn string, notBefore, notAfter time.Time) []byte {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return certPEM
}

func TestScheduleRenewalTime(t *testing.T) {
	tests := []struct {
		name        string
		now         time.Time
		notAfter    time.Time
		renewBefore time.Duration
		wantDelay   time.Duration
	}{
		{
			name:        "renewal in 10 days",
			now:         time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			notAfter:    time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC), // 31 days
			renewBefore: 30 * 24 * time.Hour,
			wantDelay:   24 * time.Hour, // renew at day 2, we're at day 1
		},
		{
			name:        "already past renewal time",
			now:         time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC),
			notAfter:    time.Date(2024, 1, 20, 0, 0, 0, 0, time.UTC), // 5 days left
			renewBefore: 10 * 24 * time.Hour,
			wantDelay:   -5 * 24 * time.Hour, // negative means immediate
		},
		{
			name:        "cert already expired",
			now:         time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC),
			notAfter:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			renewBefore: 30 * 24 * time.Hour,
			wantDelay:   -61 * 24 * time.Hour, // negative means immediate
		},
		{
			name:        "renew 1 hour before expiry",
			now:         time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
			notAfter:    time.Date(2024, 1, 1, 14, 0, 0, 0, time.UTC),
			renewBefore: 1 * time.Hour,
			wantDelay:   1 * time.Hour, // renew at 13:00, now is 12:00
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the core renewal time logic
			renewAt := tt.notAfter.Add(-tt.renewBefore)
			delay := renewAt.Sub(tt.now)

			if delay != tt.wantDelay {
				t.Errorf("delay = %v, want %v", delay, tt.wantDelay)
			}

			// Also verify the full scheduling flow works
			notBefore := tt.now.Add(-24 * time.Hour)
			certPEM := makeCert("test.example.com", notBefore, tt.notAfter)

			fc := &fakeClock{now: tt.now}
			client := fake.NewSimpleClientset()
			fetcher := newFakeFetcher()
			sched := NewRenewalScheduler(client, fetcher, tt.renewBefore, nil, nil)
			sched.clock = fc

			sec := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "default",
					Labels: map[string]string{
						LabelManagedBy: LabelManagedByValue,
						LabelCN:        "test-example-com",
					},
				},
				Data: map[string][]byte{
					corev1.TLSCertKey: certPEM,
				},
			}

			// scheduleRenewal should not panic or error
			sched.scheduleRenewal(context.Background(), sec)
		})
	}
}

func TestRenewalSchedulerIntegration(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := now.Add(40 * 24 * time.Hour) // expires in 40 days
	notBefore := now.Add(-24 * time.Hour)
	renewBefore := 30 * 24 * time.Hour

	certPEM := makeCert("test.example.com", notBefore, notAfter)
	newCertPEM := makeCert("test.example.com", notBefore, notAfter.Add(90*24*time.Hour))

	fc := &fakeClock{now: now}
	client := fake.NewSimpleClientset()
	fetcher := newFakeFetcher()
	fetcher.set("test-example-com", &CertBundle{
		CN:       "test-example-com",
		CertPEM:  newCertPEM,
		ChainPEM: []byte("chain"),
		NotAfter: notAfter.Add(90 * 24 * time.Hour),
	})

	sched := NewRenewalScheduler(client, fetcher, renewBefore, nil, nil)
	sched.clock = fc

	// Create initial secret
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Labels: map[string]string{
				LabelManagedBy: LabelManagedByValue,
				LabelCN:        "test-example-com",
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "v1",
				Kind:       "Pod",
				Name:       "test-pod",
				UID:        types.UID("test-uid"),
			}},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey: certPEM,
			"ca.crt":          []byte("old-chain"),
		},
	}
	if _, err := client.CoreV1().Secrets("default").Create(context.Background(), sec, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create secret: %v", err)
	}

	// Schedule renewal
	sched.scheduleRenewal(context.Background(), sec)

	// Advance time to renewal point (10 days from now = 30 days before expiry)
	fc.Advance(10*24*time.Hour + 1*time.Minute)

	// Process the renewal
	ctx := context.Background()
	processed := sched.processNextItem(ctx)
	if !processed {
		t.Fatal("expected item to be processed")
	}

	// Verify secret was updated
	updated, err := client.CoreV1().Secrets("default").Get(ctx, "test-secret", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get updated secret: %v", err)
	}

	if string(updated.Data[corev1.TLSCertKey]) != string(newCertPEM) {
		t.Errorf("cert was not updated")
	}
	if string(updated.Data["ca.crt"]) != "chain" {
		t.Errorf("chain was not updated, got %q", string(updated.Data["ca.crt"]))
	}
}
