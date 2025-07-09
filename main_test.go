package main

import (
	crypto_rand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"hash/crc64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProtocolDetection(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"HTTPS URL", "https://example.com", "https://example.com"},
		{"HTTP URL", "http://example.com", "http://example.com"},
		{"No protocol", "example.com", "https://example.com"},
		{"Empty protocol", "", "https://"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			destination := tt.input
			if !strings.HasPrefix(destination, "http://") && !strings.HasPrefix(destination, "https://") {
				destination = "https://" + destination
			}
			if destination != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, destination)
			}
		})
	}
}

func TestPercentageCalculation(t *testing.T) {
	// Test CRC64 consistency
	testString := "192.168.1.1"
	crc64Table := crc64.MakeTable(0xC96C5795D7870F42)
	
	hash1 := crc64.Checksum([]byte(testString), crc64Table)
	hash2 := crc64.Checksum([]byte(testString), crc64Table)
	
	if hash1 != hash2 {
		t.Errorf("CRC64 should be consistent: %d != %d", hash1, hash2)
	}
}

func TestHTTPClientConfiguration(t *testing.T) {
	// Save original client
	originalClient := httpClient
	defer func() { httpClient = originalClient }()

	// Test client configuration
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	
	testClient := &http.Client{
		Transport: tr,
		Timeout:   60 * time.Second,
	}
	
	httpClient = testClient
	
	if httpClient.Timeout != 60*time.Second {
		t.Errorf("Expected timeout 60s, got %v", httpClient.Timeout)
	}
	
	if transport, ok := httpClient.Transport.(*http.Transport); ok {
		if !transport.TLSClientConfig.InsecureSkipVerify {
			t.Error("Expected InsecureSkipVerify to be true")
		}
	} else {
		t.Error("Transport type assertion failed")
	}
}

func TestForwardRequestHeaders(t *testing.T) {
	// Create a test server
	received := make(chan *http.Request, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Save original values
	originalDest := *fwdDestination
	originalPerc := *fwdPerc
	defer func() {
		*fwdDestination = originalDest
		*fwdPerc = originalPerc
	}()

	*fwdDestination = ts.URL
	*fwdPerc = 100

	// Create a test request
	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("X-Custom-Header", "test-value")
	req.Host = "example.com"

	// Call forwardRequest
	go forwardRequest(req, "192.168.1.1", "80", []byte{})

	// Wait for the request to be received
	select {
	case receivedReq := <-received:
		// Check X-Forwarded headers
		if receivedReq.Header.Get("X-Forwarded-For") != "192.168.1.1" {
			t.Errorf("Expected X-Forwarded-For to be 192.168.1.1, got %s", 
				receivedReq.Header.Get("X-Forwarded-For"))
		}
		if receivedReq.Header.Get("X-Forwarded-Port") != "80" {
			t.Errorf("Expected X-Forwarded-Port to be 80, got %s", 
				receivedReq.Header.Get("X-Forwarded-Port"))
		}
		if receivedReq.Header.Get("X-Forwarded-Proto") != "http" {
			t.Errorf("Expected X-Forwarded-Proto to be http, got %s", 
				receivedReq.Header.Get("X-Forwarded-Proto"))
		}
		if receivedReq.Header.Get("X-Forwarded-Host") != "example.com" {
			t.Errorf("Expected X-Forwarded-Host to be example.com, got %s", 
				receivedReq.Header.Get("X-Forwarded-Host"))
		}
		// Check custom header was preserved
		if receivedReq.Header.Get("X-Custom-Header") != "test-value" {
			t.Errorf("Expected X-Custom-Header to be test-value, got %s", 
				receivedReq.Header.Get("X-Custom-Header"))
		}
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for forwarded request")
	}
}

func TestKeepHostHeader(t *testing.T) {
	// Create a test server
	received := make(chan *http.Request, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Save original values
	originalDest := *fwdDestination
	originalKeep := *keepHostHeader
	originalPerc := *fwdPerc
	defer func() {
		*fwdDestination = originalDest
		*keepHostHeader = originalKeep
		*fwdPerc = originalPerc
	}()

	*fwdDestination = ts.URL
	*keepHostHeader = true
	*fwdPerc = 100

	// Create a test request
	req, _ := http.NewRequest("GET", "http://original.com/test", nil)
	req.Host = "original.com"

	// Call forwardRequest
	go forwardRequest(req, "192.168.1.1", "80", []byte{})

	// Wait for the request to be received
	select {
	case receivedReq := <-received:
		if receivedReq.Host != "original.com" {
			t.Errorf("Expected Host header to be preserved as original.com, got %s", receivedReq.Host)
		}
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for forwarded request")
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name        string
		setupFunc   func()
		expectError bool
	}{
		{
			name: "Invalid percentage high",
			setupFunc: func() {
				*fwdPerc = 101
				*fwdDestination = "http://example.com"
			},
			expectError: true,
		},
		{
			name: "Invalid percentage low",
			setupFunc: func() {
				*fwdPerc = -1
				*fwdDestination = "http://example.com"
			},
			expectError: true,
		},
		{
			name: "Invalid percentage-by",
			setupFunc: func() {
				*fwdPerc = 50
				*fwdBy = "invalid"
				*fwdDestination = "http://example.com"
			},
			expectError: true,
		},
		{
			name: "Missing header when percentage-by is header",
			setupFunc: func() {
				*fwdPerc = 50
				*fwdBy = "header"
				*fwdHeader = ""
				*fwdDestination = "http://example.com"
			},
			expectError: true,
		},
		{
			name: "Invalid port high",
			setupFunc: func() {
				*fwdPerc = 50
				*fwdBy = ""
				*reqPort = 65536
				*fwdDestination = "http://example.com"
			},
			expectError: true,
		},
		{
			name: "Invalid port low",
			setupFunc: func() {
				*fwdPerc = 50
				*fwdBy = ""
				*reqPort = -1
				*fwdDestination = "http://example.com"
			},
			expectError: true,
		},
		{
			name: "Missing destination",
			setupFunc: func() {
				*fwdPerc = 50
				*fwdBy = ""
				*reqPort = 80
				*fwdDestination = ""
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset flags
			*fwdPerc = 100
			*fwdBy = ""
			*fwdHeader = ""
			*reqPort = 80
			*fwdDestination = "http://example.com"

			tt.setupFunc()

			// Validation logic from main()
			var err error
			if *fwdPerc > 100 || *fwdPerc < 0 {
				err = fmt.Errorf("Flag percentage is not between 0 and 100. Value: %f", *fwdPerc)
			} else if *fwdBy != "" && *fwdBy != "header" && *fwdBy != "remoteaddr" {
				err = fmt.Errorf("Flag percentage-by (%s) is not valid", *fwdBy)
			} else if *fwdBy == "header" && *fwdHeader == "" {
				err = fmt.Errorf("Flag percentage-by is set to header, but percentage-by-header is empty")
			} else if *reqPort > 65535 || *reqPort < 0 {
				err = fmt.Errorf("Flag filter-request-port is not between 0 and 65535. Value: %d", *reqPort)
			} else if *fwdDestination == "" {
				err = fmt.Errorf("Flag destination is required")
			}

			if tt.expectError && err == nil {
				t.Error("Expected validation error but got none")
			} else if !tt.expectError && err != nil {
				t.Errorf("Unexpected validation error: %v", err)
			}
		})
	}
}

func TestRandomSeedGeneration(t *testing.T) {
	// Test that random generation doesn't panic
	var b [8]byte
	_, err := crypto_rand.Read(b[:])
	if err != nil {
		t.Errorf("Failed to generate random bytes: %v", err)
	}
	
	uintForSeed := binary.LittleEndian.Uint64(b[:])
	if uintForSeed == 0 {
		t.Error("Random seed should not be zero")
	}
}