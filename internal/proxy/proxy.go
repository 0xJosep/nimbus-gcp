package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

var (
	mu             sync.Mutex
	rateLimit      int // requests per second; 0 means unlimited
)

// SetProxy sets the HTTP_PROXY and HTTPS_PROXY environment variables for the
// current process so that all subsequent HTTP clients pick up the proxy.
func SetProxy(proxyURL string) error {
	if _, err := url.Parse(proxyURL); err != nil {
		return fmt.Errorf("invalid proxy URL %q: %w", proxyURL, err)
	}
	os.Setenv("HTTP_PROXY", proxyURL)
	os.Setenv("HTTPS_PROXY", proxyURL)
	return nil
}

// SetRateLimit stores the global rate limit (requests per second).
func SetRateLimit(requestsPerSecond int) {
	mu.Lock()
	defer mu.Unlock()
	rateLimit = requestsPerSecond
}

// getRateLimit returns the current rate limit.
func getRateLimit() int {
	mu.Lock()
	defer mu.Unlock()
	return rateLimit
}

// rateLimitedTransport wraps an http.RoundTripper with token-bucket rate limiting.
type rateLimitedTransport struct {
	base   http.RoundTripper
	tokens chan struct{}
	done   chan struct{}
}

// NewTransport returns an http.RoundTripper that applies proxy settings and
// optional rate limiting. If proxyURL is non-empty, the transport is configured
// to route through that proxy. If rps > 0, a channel-based token bucket limits
// the number of requests per second.
func NewTransport(proxyURL string, rps int) http.RoundTripper {
	base := http.DefaultTransport.(*http.Transport).Clone()

	if proxyURL != "" {
		if u, err := url.Parse(proxyURL); err == nil {
			base.Proxy = http.ProxyURL(u)
		}
	}

	if rps <= 0 {
		return base
	}

	tokens := make(chan struct{}, rps)
	done := make(chan struct{})

	// Fill the bucket initially.
	for i := 0; i < rps; i++ {
		tokens <- struct{}{}
	}

	// Refill the token bucket at the configured rate.
	go func() {
		ticker := time.NewTicker(time.Second / time.Duration(rps))
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				select {
				case tokens <- struct{}{}:
				default:
					// Bucket full, discard token.
				}
			}
		}
	}()

	return &rateLimitedTransport{
		base:   base,
		tokens: tokens,
		done:   done,
	}
}

// RoundTrip implements http.RoundTripper. It blocks until a rate-limit token
// is available, then delegates to the underlying transport.
func (t *rateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	<-t.tokens // acquire token (blocks if rate exceeded)
	return t.base.RoundTrip(req)
}
