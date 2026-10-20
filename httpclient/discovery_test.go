// Copyright (c) 2026 Method Security. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.

package httpclient

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCustomTransportProbeIdentity(t *testing.T) {
	const hostname = "Product.Invalid"
	identity := make(chan [3]string, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity <- [3]string{r.Host, r.TLS.ServerName, r.UserAgent()}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
		TLSClientConfig: &tls.Config{
			ServerName: hostname, InsecureSkipVerify: true, //nolint:gosec // Self-signed local fixture.
			MinVersion: tls.VersionTLS10, //nolint:gosec // Preserve discovery's legacy TLS configuration.
		},
		DisableKeepAlives: true,
	}
	c := New(WithTransport(transport), WithDefaultHeaders(map[string]string{"User-Agent": "discovery-fixture"}))
	defer c.CloseIdleConnections()
	cloned := c.httpClient.Transport.(*http.Transport)
	if cloned == transport || cloned.TLSClientConfig == transport.TLSClientConfig {
		t.Fatal("transport and TLS configuration must be cloned")
	}
	if cloned.ForceAttemptHTTP2 || !cloned.DisableKeepAlives || cloned.TLSClientConfig.MinVersion != tls.VersionTLS10 {
		t.Fatal("custom transport settings were replaced with defaults")
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodHead, "https://"+hostname+":8443/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Probe(req)
	if err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected HTTP evidence despite non-success status: %+v, %v", resp, err)
	}
	if got := <-identity; got != [3]string{hostname + ":8443", hostname, "discovery-fixture"} {
		t.Fatalf("wrong Host, SNI, or User-Agent: %q", got)
	}
	if req.Header.Get("User-Agent") != "" {
		t.Fatal("Probe mutated the caller's headers")
	}

	// Buffered methods must use the same pinned transport too.
	_, err = c.Get(context.Background(), "https://"+hostname+":8443/")
	if err != nil {
		t.Fatal(err)
	}
	<-identity
}

func TestProbeDoesNotFollowOrParseRedirect(t *testing.T) {
	for _, location := range []string{"/other", "https://other.invalid/", "://invalid"} {
		t.Run(location, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/" {
					t.Error("Probe followed a redirect")
				}
				w.Header().Set("Location", location)
				w.WriteHeader(http.StatusFound)
			}))
			defer server.Close()
			c := New()
			defer c.CloseIdleConnections()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := c.Probe(req)
			if err != nil || resp.StatusCode != http.StatusFound || resp.Headers.Get("Location") != location {
				t.Fatalf("lost redirect evidence: %+v, %v", resp, err)
			}
			if resp.Body != nil || resp.RedirectChain != nil {
				t.Fatalf("Probe returned a body or redirect chain: %+v", resp)
			}
		})
	}
}

func TestProbeDoesNotWaitForBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	c := New(WithTimeout(2 * time.Second))
	defer c.CloseIdleConnections()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Probe(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("Probe waited for the stalled body: %+v, %v", resp, err)
	}
}

func TestProbeTimeoutAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	for _, tc := range []struct {
		name    string
		timeout time.Duration
		cancel  bool
		want    error
	}{
		{"client-timeout", 50 * time.Millisecond, false, context.DeadlineExceeded},
		{"canceled-parent", 0, true, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if tc.cancel {
				cancel()
			}
			c := New(WithTimeout(tc.timeout))
			defer c.CloseIdleConnections()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Probe(req); !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

func TestResponseBodyLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello")
	}))
	defer server.Close()
	for _, limit := range []int64{-1, 0, 4, 5, 6} {
		c := New(WithMaxResponseBodyBytes(limit))
		resp, err := c.Get(context.Background(), server.URL)
		c.CloseIdleConnections()
		if limit == 4 {
			if !errors.Is(err, ErrResponseBodyTooLarge) || resp == nil || string(resp.Body) != "hell" || resp.StatusCode != http.StatusOK {
				t.Fatalf("expected bounded body and size error: %+v, %v", resp, err)
			}
		} else if err != nil || string(resp.Body) != "hello" {
			t.Fatalf("limit %d: %+v, %v", limit, resp, err)
		}
	}
}

func TestDefaultTransportUnchanged(t *testing.T) {
	c := New(WithTransport(nil))
	transport := c.httpClient.Transport.(*http.Transport)
	if !transport.ForceAttemptHTTP2 || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("default HTTP/2 or TLS behavior changed")
	}
	if c.options.MaxResponseBodyBytes != 0 {
		t.Fatal("default response buffering must remain unlimited")
	}
}

func TestCustomTransportProxyDoesNotMutateSource(t *testing.T) {
	transport := &http.Transport{}
	c := New(WithTransport(transport), WithHTTPProxy("http://127.0.0.1:8080"))
	cloned := c.httpClient.Transport.(*http.Transport)
	if transport.Proxy != nil || cloned.Proxy == nil {
		t.Fatal("explicit proxy must apply only to the cloned transport")
	}
}

func TestProbeInvalidProxy(t *testing.T) {
	c := New(WithSOCKSProxy("http://127.0.0.1:1080"))
	req, err := http.NewRequestWithContext(context.Background(), http.MethodHead, "http://unused.invalid/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Probe(req); err == nil || !strings.Contains(err.Error(), "proxy configuration failed") {
		t.Fatalf("expected proxy configuration failure: %v", err)
	}
}
