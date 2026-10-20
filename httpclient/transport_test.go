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
	"testing"
)

func TestCustomTransportIdentity(t *testing.T) {
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
			MinVersion: tls.VersionTLS10, //nolint:gosec // Preserve the caller's explicit legacy TLS configuration.
		},
		DisableKeepAlives: true,
	}
	c := New(WithTransport(transport), WithDefaultHeaders(map[string]string{"User-Agent": "transport-fixture"}))
	defer c.CloseIdleConnections()
	cloned := c.httpClient.Transport.(*http.Transport)
	if cloned == transport || cloned.TLSClientConfig == transport.TLSClientConfig {
		t.Fatal("transport and TLS configuration must be cloned")
	}
	if cloned.ForceAttemptHTTP2 || !cloned.DisableKeepAlives || cloned.TLSClientConfig.MinVersion != tls.VersionTLS10 {
		t.Fatal("custom transport settings were replaced with defaults")
	}

	resp, err := c.Head(context.Background(), "https://"+hostname+":8443/")
	if err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unexpected HEAD response: %+v, %v", resp, err)
	}
	if got := <-identity; got != [3]string{hostname + ":8443", hostname, "transport-fixture"} {
		t.Fatalf("wrong Host, SNI, or User-Agent: %q", got)
	}
	_, err = c.Get(context.Background(), "https://"+hostname+":8443/")
	if err != nil {
		t.Fatal(err)
	}
	<-identity
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

func TestIsAliveWithBodyLimit(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusForbidden, http.StatusNotFound, http.StatusBadGateway} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "oversized response")
			}))
			defer server.Close()
			c := New(WithMaxResponseBodyBytes(4))
			defer c.CloseIdleConnections()
			want := status != http.StatusNotFound && status != http.StatusBadGateway
			if got := c.IsAlive(context.Background(), server.URL); got != want {
				t.Fatalf("status %d: IsAlive = %t, want %t", status, got, want)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if c.IsAlive(ctx, server.URL) {
				t.Fatal("canceled request must not be considered alive")
			}
		})
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
