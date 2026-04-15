// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.

package httpclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client wraps http.Client with Method-specific defaults and helpers.
type Client struct {
	httpClient *http.Client
	options    Options
}

// Options configures the HTTP client behavior.
type Options struct {
	Timeout        time.Duration
	VerifyTLS      bool
	MaxRedirects   int
	TrackRedirects bool
}

// Option is a functional option for configuring the HTTP client.
type Option func(*Options)

// WithTimeout sets the HTTP request timeout.
func WithTimeout(d time.Duration) Option {
	return func(o *Options) {
		o.Timeout = d
	}
}

// WithTLSVerify controls whether TLS certificate verification is enabled.
func WithTLSVerify(verify bool) Option {
	return func(o *Options) {
		o.VerifyTLS = verify
	}
}

// WithMaxRedirects sets the maximum number of redirects to follow.
// Set to 0 to disable redirects. Default is 10.
func WithMaxRedirects(n int) Option {
	return func(o *Options) {
		o.MaxRedirects = n
	}
}

// WithRedirectTracking enables tracking of the full redirect chain in responses.
func WithRedirectTracking() Option {
	return func(o *Options) {
		o.TrackRedirects = true
	}
}

// defaultOptions returns the default client options.
func defaultOptions() Options {
	return Options{
		Timeout:        30 * time.Second,
		VerifyTLS:      true,
		MaxRedirects:   10,
		TrackRedirects: false,
	}
}

// New creates a new HTTP client with the given options.
func New(opts ...Option) *Client {
	options := defaultOptions()
	for _, opt := range opts {
		opt(&options)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: !options.VerifyTLS, //nolint:gosec // configurable by caller
		},
	}

	client := &http.Client{
		Timeout:   options.Timeout,
		Transport: transport,
	}

	if options.MaxRedirects == 0 {
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else if options.MaxRedirects != 10 {
		max := options.MaxRedirects
		client.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
			if len(via) >= max {
				return fmt.Errorf("stopped after %d redirects", max)
			}
			return nil
		}
	}

	return &Client{
		httpClient: client,
		options:    options,
	}
}

// Response wraps an HTTP response with additional metadata.
type Response struct {
	StatusCode    int
	Headers       http.Header
	Body          []byte
	RedirectChain []RedirectHop
}

// RedirectHop records a single redirect in the chain.
type RedirectHop struct {
	URL        string
	StatusCode int
}

// Get performs an HTTP GET request.
func (c *Client) Get(ctx context.Context, url string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	return c.Do(req)
}

// Post performs an HTTP POST request with a JSON body.
func (c *Client) Post(ctx context.Context, url string, body any) (*Response, error) {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(jsonBody)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.Do(req)
}

// Do executes an HTTP request and returns a Response.
func (c *Client) Do(req *http.Request) (*Response, error) {
	var redirectChain []RedirectHop

	if c.options.TrackRedirects {
		originalCheckRedirect := c.httpClient.CheckRedirect
		c.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 {
				prev := via[len(via)-1]
				hop := RedirectHop{URL: prev.URL.String()}
				if prev.Response != nil {
					hop.StatusCode = prev.Response.StatusCode
				}
				redirectChain = append(redirectChain, hop)
			}
			if originalCheckRedirect != nil {
				return originalCheckRedirect(req, via)
			}
			if len(via) >= 10 {
				return fmt.Errorf("stopped after %d redirects", 10)
			}
			return nil
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return &Response{
		StatusCode:    resp.StatusCode,
		Headers:       resp.Header,
		Body:          body,
		RedirectChain: redirectChain,
	}, nil
}

// GetJSON performs a GET request and unmarshals the JSON response into dest.
func (c *Client) GetJSON(ctx context.Context, url string, dest any) (*Response, error) {
	resp, err := c.Get(ctx, url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	if err := json.Unmarshal(resp.Body, dest); err != nil {
		return resp, fmt.Errorf("failed to parse JSON response: %w", err)
	}
	return resp, nil
}

// PostJSON performs a POST request with a JSON body and unmarshals the response into dest.
func (c *Client) PostJSON(ctx context.Context, url string, body any, dest any) (*Response, error) {
	resp, err := c.Post(ctx, url, body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	if err := json.Unmarshal(resp.Body, dest); err != nil {
		return resp, fmt.Errorf("failed to parse JSON response: %w", err)
	}
	return resp, nil
}

// IsAlive checks if a URL responds with a non-404/502 status code.
func (c *Client) IsAlive(ctx context.Context, url string) bool {
	resp, err := c.Get(ctx, url)
	if err != nil {
		return false
	}
	return resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusBadGateway
}
