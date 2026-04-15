// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.

package httpclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected JSON content type, got %s", r.Header.Get("Content-Type"))
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
	if len(resp.RedirectChain) != 2 {
		t.Fatalf("expected 2 redirects, got %d: %+v", len(resp.RedirectChain), resp.RedirectChain)
	}
	// First hop: /start -> /middle (initial request has no Response in via)
	if resp.RedirectChain[0].URL != server.URL+"/start" {
		t.Errorf("expected first redirect from /start, got %s", resp.RedirectChain[0].URL)
	}
	// Second hop: /middle -> /end
	if resp.RedirectChain[1].URL != server.URL+"/middle" {
		t.Errorf("expected second redirect from /middle, got %s", resp.RedirectChain[1].URL)
	}
	if resp.RedirectChain[1].StatusCode != http.StatusFound {
		t.Errorf("expected second redirect 302, got %d", resp.RedirectChain[1].StatusCode)
	}
}
