// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.

package httpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestNewDefaults(t *testing.T) {
	c := New()
	if c.options.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", c.options.Timeout)
	}
	if !c.options.VerifyTLS {
		t.Error("expected TLS verification enabled by default")
	}
	if c.options.MaxRedirects != 10 {
		t.Errorf("expected 10 max redirects, got %d", c.options.MaxRedirects)
	}
}

func TestNewWithOptions(t *testing.T) {
	c := New(
		WithTimeout(5*time.Second),
		WithTLSVerify(false),
		WithMaxRedirects(3),
		WithBlockCrossDomainRedirects(),
		WithDefaultHeaders(map[string]string{"User-Agent": "test-agent"}),
	)
	if c.options.Timeout != 5*time.Second {
		t.Errorf("expected 5s timeout, got %v", c.options.Timeout)
	}
	if c.options.VerifyTLS {
		t.Error("expected TLS verification disabled")
	}
	if c.options.MaxRedirects != 3 {
		t.Errorf("expected 3 max redirects, got %d", c.options.MaxRedirects)
	}
	if !c.options.BlockCrossDomainRedirects {
		t.Error("expected cross-domain redirect blocking enabled")
	}
	if c.defaultHeaders["User-Agent"] != "test-agent" {
		t.Error("expected default User-Agent header")
	}
}

func TestGet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Custom", "test")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))
	defer server.Close()

	c := New()
	resp, err := c.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if string(resp.Body) != "hello" {
		t.Errorf("expected 'hello', got '%s'", string(resp.Body))
	}
	if resp.Headers.Get("X-Custom") != "test" {
		t.Errorf("expected custom header 'test', got '%s'", resp.Headers.Get("X-Custom"))
	}
}

func TestDefaultHeaders(t *testing.T) {
	var receivedUA string
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		receivedUA = r.Header.Get("User-Agent")
	}))
	defer server.Close()

	c := New(WithDefaultHeaders(map[string]string{"User-Agent": "MethodScan/1.0"}))
	_, _ = c.Get(context.Background(), server.URL)
	if receivedUA != "MethodScan/1.0" {
		t.Errorf("expected default User-Agent, got '%s'", receivedUA)
	}
}

func TestGetWithHeaders(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
	}))
	defer server.Close()

	c := New()
	_, _ = c.GetWithHeaders(context.Background(), server.URL, map[string]string{
		"Authorization": "Bearer token123",
	})
	if receivedAuth != "Bearer token123" {
		t.Errorf("expected auth header, got '%s'", receivedAuth)
	}
}

func TestPerRequestHeadersOverrideDefaults(t *testing.T) {
	var receivedUA string
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		receivedUA = r.Header.Get("User-Agent")
	}))
	defer server.Close()

	c := New(WithDefaultHeaders(map[string]string{"User-Agent": "default"}))
	_, _ = c.GetWithHeaders(context.Background(), server.URL, map[string]string{
		"User-Agent": "override",
	})
	if receivedUA != "override" {
		t.Errorf("expected override User-Agent, got '%s'", receivedUA)
	}
}

func TestHead(t *testing.T) {
	var receivedMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		w.Header().Set("X-Server", "test")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := New()
	resp, err := c.Head(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedMethod != http.MethodHead {
		t.Errorf("expected HEAD method, got %s", receivedMethod)
	}
	if resp.Headers.Get("X-Server") != "test" {
		t.Errorf("expected server header, got '%s'", resp.Headers.Get("X-Server"))
	}
}

func TestPostForm(t *testing.T) {
	var receivedContentType string
	var receivedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := New()
	_, err := c.PostForm(context.Background(), server.URL, url.Values{
		"username": {"admin"},
		"password": {"secret"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedContentType != "application/x-www-form-urlencoded" {
		t.Errorf("expected form content type, got '%s'", receivedContentType)
	}
	parsed, _ := url.ParseQuery(receivedBody)
	if parsed.Get("username") != "admin" {
		t.Errorf("expected username=admin, got '%s'", parsed.Get("username"))
	}
}

func TestRequest(t *testing.T) {
	var receivedMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := New()
	_, err := c.Request(context.Background(), http.MethodPut, server.URL, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedMethod != http.MethodPut {
		t.Errorf("expected PUT, got %s", receivedMethod)
	}
}

func TestGetJSON(t *testing.T) {
	type testResp struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(testResp{Name: "test", Value: 42})
	}))
	defer server.Close()

	c := New()
	var dest testResp
	_, err := c.GetJSON(context.Background(), server.URL, &dest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dest.Name != "test" || dest.Value != 42 {
		t.Errorf("unexpected result: %+v", dest)
	}
}

func TestPostJSON(t *testing.T) {
	type reqBody struct {
		Username string `json:"username"`
	}
	type respBody struct {
		Result string `json:"result"`
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		var body reqBody
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(respBody{Result: "ok:" + body.Username})
	}))
	defer server.Close()

	c := New()
	var dest respBody
	_, err := c.PostJSON(context.Background(), server.URL, reqBody{Username: "test"}, &dest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dest.Result != "ok:test" {
		t.Errorf("expected 'ok:test', got '%s'", dest.Result)
	}
}

func TestGetJSONNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	c := New()
	var dest map[string]any
	resp, err := c.GetJSON(context.Background(), server.URL, &dest)
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestIsAlive(t *testing.T) {
	alive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer alive.Close()

	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer dead.Close()

	c := New()
	if !c.IsAlive(context.Background(), alive.URL) {
		t.Error("expected alive server to return true")
	}
	if c.IsAlive(context.Background(), dead.URL) {
		t.Error("expected dead server to return false")
	}
}

func TestNoRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/other", http.StatusFound)
	}))
	defer server.Close()

	c := New(WithMaxRedirects(0))
	resp, err := c.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected 302 with no redirects, got %d", resp.StatusCode)
	}
}

func TestRedirectTracking(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/middle", http.StatusFound)
	})
	mux.HandleFunc("/middle", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/end", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/end", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("done"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	c := New(WithRedirectTracking())
	resp, err := c.Get(context.Background(), server.URL+"/start")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if string(resp.Body) != "done" {
		t.Errorf("expected body 'done', got '%s'", string(resp.Body))
	}
	if len(resp.RedirectChain) != 2 {
		t.Fatalf("expected 2 redirects, got %d: %+v", len(resp.RedirectChain), resp.RedirectChain)
	}
	if resp.RedirectChain[0].StatusCode != http.StatusFound {
		t.Errorf("expected first hop 302, got %d", resp.RedirectChain[0].StatusCode)
	}
	if resp.RedirectChain[1].StatusCode != http.StatusMovedPermanently {
		t.Errorf("expected second hop 301, got %d", resp.RedirectChain[1].StatusCode)
	}
}

func TestBlockCrossDomainRedirect(t *testing.T) {
	// Server that redirects to a different host.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://evil.example.com/steal", http.StatusFound)
	}))
	defer server.Close()

	c := New(WithBlockCrossDomainRedirects())
	_, err := c.Get(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for cross-domain redirect")
	}
	if !contains(err.Error(), "cross-domain redirect blocked") {
		t.Errorf("expected cross-domain error, got: %v", err)
	}
}

func TestSameDomainRedirectAllowed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	c := New(WithBlockCrossDomainRedirects())
	resp, err := c.Get(context.Background(), server.URL+"/a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestMaxRedirectsExceeded(t *testing.T) {
	redirectCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectCount++
		http.Redirect(w, r, fmt.Sprintf("%s?loop=%d", r.URL.Path, redirectCount), http.StatusFound)
	}))
	defer server.Close()

	c := New(WithMaxRedirects(2))
	resp, err := c.Get(context.Background(), server.URL+"/loop")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// After max redirects, we return the last redirect response as-is.
	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected 302 after max redirects, got %d", resp.StatusCode)
	}
}

func TestMethodPreservedOn307(t *testing.T) {
	var methods []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		http.Redirect(w, r, "/api/v2", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/api/v2", func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	c := New()
	_, err := c.Request(context.Background(), http.MethodPost, server.URL+"/api", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(methods) != 2 || methods[0] != "POST" || methods[1] != "POST" {
		t.Errorf("expected POST preserved on 307 redirect, got methods: %v", methods)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
