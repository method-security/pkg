// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Method-Security/pkg/httpclient"
)

func main() {
	// Example 1: HTTP/HTTPS Proxy
	httpClient := httpclient.New(
		httpclient.WithHTTPProxy("http://proxy.example.com:8080"),
	)

	resp, err := httpClient.Get(context.Background(), "https://api.example.com/data")
	if err != nil {
		log.Fatalf("HTTP request failed: %v", err)
	}
	fmt.Printf("HTTP Proxy Response: %d\n", resp.StatusCode)

	// Example 2: HTTP Proxy with Authentication
	httpClientWithAuth := httpclient.New(
		httpclient.WithHTTPProxy("http://user:password@proxy.example.com:8080"),
	)

	resp, err = httpClientWithAuth.Get(context.Background(), "https://api.example.com/data")
	if err != nil {
		log.Fatalf("HTTP request with auth failed: %v", err)
	}
	fmt.Printf("HTTP Proxy with Auth Response: %d\n", resp.StatusCode)

	// Example 3: SOCKS5 Proxy
	socksClient := httpclient.New(
		httpclient.WithSOCKSProxy("socks5://proxy.example.com:1080"),
	)

	resp, err = socksClient.Get(context.Background(), "https://api.example.com/data")
	if err != nil {
		log.Fatalf("SOCKS5 request failed: %v", err)
	}
	fmt.Printf("SOCKS5 Proxy Response: %d\n", resp.StatusCode)

	// Example 4: SOCKS5 Proxy with Authentication
	socksClientWithAuth := httpclient.New(
		httpclient.WithSOCKSProxy("socks5://user:password@proxy.example.com:1080"),
	)

	resp, err = socksClientWithAuth.Get(context.Background(), "https://api.example.com/data")
	if err != nil {
		log.Fatalf("SOCKS5 request with auth failed: %v", err)
	}
	fmt.Printf("SOCKS5 Proxy with Auth Response: %d\n", resp.StatusCode)

	// Example 5: Combining Proxy with Other Options
	advancedClient := httpclient.New(
		httpclient.WithHTTPProxy("http://proxy.example.com:8080"),
		httpclient.WithTimeout(30*time.Second),
		httpclient.WithTLSVerify(false),
		httpclient.WithDefaultHeaders(map[string]string{
			"User-Agent": "MethodSecurity/1.0",
		}),
	)

	resp, err = advancedClient.Get(context.Background(), "https://api.example.com/data")
	if err != nil {
		log.Fatalf("Advanced request failed: %v", err)
	}
	fmt.Printf("Advanced Client Response: %d\n", resp.StatusCode)

	// Note: If both HTTPProxy and SOCKSProxy are specified, SOCKS5 takes precedence
}
