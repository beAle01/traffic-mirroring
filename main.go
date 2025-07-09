
package main

import (
	"bufio"
	"bytes"
	crypto_rand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"hash/crc64"
	"io"
	"log"
	math_rand "math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// Command line flags
var fwdDestination = flag.String("destination", "", "Destination of the forwarded requests (e.g., https://example.com or http://example.com).")
var fwdPerc = flag.Float64("percentage", 100, "Must be between 0 and 100.")
var fwdBy = flag.String("percentage-by", "", "Can be empty. Otherwise, valid values are: header, remoteaddr.")
var fwdHeader = flag.String("percentage-by-header", "", "If percentage-by is header, then specify the header here.")
var reqPort = flag.Int("filter-request-port", 80, "Must be between 0 and 65535.")
var keepHostHeader = flag.Bool("keep-host-header", false, "Keep Host header from original request.")
var tlsInsecure = flag.Bool("tls-insecure", false, "Skip TLS certificate verification (not recommended for production).")
var httpTimeout = flag.Duration("http-timeout", 30*time.Second, "HTTP client timeout.")

// httpStreamFactory implements tcpassembly.StreamFactory for creating HTTP streams
type httpStreamFactory struct{}

// httpStream handles the actual decoding of HTTP requests from TCP streams
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

// httpClient is the global HTTP client with connection pooling and HTTPS support
var httpClient *http.Client

func init() {
	// Initialize HTTP client with connection pooling and HTTPS support
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false, // Will be configured based on flags
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
	
	httpClient = &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second, // Will be configured based on flags
	}
}

// New creates a new HTTP stream for the given network flow
func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	// Start processing the stream in a separate goroutine
	go hstream.run()

	return &hstream.r
}

// run processes HTTP requests from the TCP stream
func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			// End of stream reached
			return
		} else if err != nil {
			log.Println("error reading stream", h.net, h.transport, ":", err)
			continue
		} else {
			// Extract source IP and destination port from the flow
			reqSourceIP := h.net.Src().String()
			reqDestinationPort := h.transport.Dst().String()
			// Read the entire request body
			body, bErr := io.ReadAll(req.Body)
			if bErr != nil {
				log.Printf("error reading request body: %v", bErr)
				continue
			}
			req.Body.Close()
			// Forward the request asynchronously
			go forwardRequest(req, reqSourceIP, reqDestinationPort, body)
		}
	}
}

// forwardRequest forwards an HTTP request to the destination with percentage-based filtering
func forwardRequest(req *http.Request, reqSourceIP string, reqDestinationPort string, body []byte) {
	// Apply percentage-based filtering if not forwarding 100% of traffic
	if *fwdPerc != 100 {
		var uintForSeed uint64

		if *fwdBy == "" {
			// Random sampling: generate cryptographically secure random seed
			var b [8]byte
			_, err := crypto_rand.Read(b[:])
			if err != nil {
				log.Println("error generating crypto random unit for seed", ":", err)
				return
			}
			// Convert random bytes to uint64 seed
			uintForSeed = binary.LittleEndian.Uint64(b[:])
		} else {
			// Deterministic sampling: use header value or IP address for consistent hashing
			strForSeed := ""
			if *fwdBy == "header" {
				strForSeed = req.Header.Get(*fwdHeader)
			} else {
				strForSeed = reqSourceIP
			}
			crc64Table := crc64.MakeTable(0xC96C5795D7870F42)
			// Generate deterministic seed from string using CRC64
			uintForSeed = crc64.Checksum([]byte(strForSeed), crc64Table)
		}

		// Generate consistent random percentage from seed
		source := math_rand.NewSource(int64(uintForSeed))
		rng := math_rand.New(source)
		randomPercent := rng.Float64() * 100
		// Skip request if it falls outside the forwarding percentage
		if randomPercent > *fwdPerc {
			return
		}
	}


	// Ensure destination URL has proper protocol prefix
	destination := *fwdDestination
	if !strings.HasPrefix(destination, "http://") && !strings.HasPrefix(destination, "https://") {
		// Default to HTTPS if no protocol specified
		destination = "https://" + destination
	}

	// Construct the full URL by combining destination with original request URI
	url := fmt.Sprintf("%s%s", destination, req.RequestURI)

	// Create new HTTP request with the same method and body
	forwardReq, err := http.NewRequest(req.Method, url, bytes.NewReader(body))
	if err != nil {
		log.Printf("error creating forward request: %v", err)
		return
	}


	// Copy all headers from original request to forwarded request
	for header, values := range req.Header {
		for _, value := range values {
			forwardReq.Header.Add(header, value)
		}
	}

	// Add X-Forwarded-For header with client IP
	forwardReq.Header.Add("X-Forwarded-For", reqSourceIP)

	// Set X-Forwarded headers if not already present
	if forwardReq.Header.Get("X-Forwarded-Port") == "" {
		forwardReq.Header.Set("X-Forwarded-Port", reqDestinationPort)
	}
	if forwardReq.Header.Get("X-Forwarded-Proto") == "" {
		// Determine protocol based on port or destination URL
		proto := "http"
		if reqDestinationPort == "443" || strings.HasPrefix(destination, "https://") {
			proto = "https"
		}
		forwardReq.Header.Set("X-Forwarded-Proto", proto)
	}
	if forwardReq.Header.Get("X-Forwarded-Host") == "" {
		forwardReq.Header.Set("X-Forwarded-Host", req.Host)
	}

	// Preserve original Host header if requested
	if *keepHostHeader {
		forwardReq.Host = req.Host
	}


	// Execute the forwarded request
	resp, rErr := httpClient.Do(forwardReq)
	if rErr != nil {
		log.Printf("forward request error for %s: %v", url, rErr)
		return
	}

	defer resp.Body.Close()
	// Response body is read and discarded to prevent connection leaks
}


// openTCPClient starts a TCP listener for AWS NLB health checks
func openTCPClient() {
	ln, err := net.Listen("tcp", ":4789")
	if err != nil {
		// TCP listener is critical for NLB health checks
		log.Println("error listening on TCP", ":", err)
		os.Exit(1)
	}
	log.Println("listening on TCP 4789")
	for {
		// Accept and immediately close connections for health check purposes
		conn, _ := ln.Accept()
		conn.Close()
	}
}

func main() {
	defer util.Run()()
	var handle *pcap.Handle
	var err error

	flag.Parse()
	
	// Configure HTTP client based on command line flags
	if transport, ok := httpClient.Transport.(*http.Transport); ok {
		transport.TLSClientConfig.InsecureSkipVerify = *tlsInsecure
	}
	httpClient.Timeout = *httpTimeout
	
	// Validate command line arguments
	if *fwdPerc > 100 || *fwdPerc < 0 {
		err = fmt.Errorf("flag percentage is not between 0 and 100, value: %f", *fwdPerc)
	} else if *fwdBy != "" && *fwdBy != "header" && *fwdBy != "remoteaddr" {
		err = fmt.Errorf("flag percentage-by (%s) is not valid", *fwdBy)
	} else if *fwdBy == "header" && *fwdHeader == "" {
		err = fmt.Errorf("flag percentage-by is set to header, but percentage-by-header is empty")
	} else if *reqPort > 65535 || *reqPort < 0 {
		err = fmt.Errorf("flag filter-request-port is not between 0 and 65535, value: %d", *reqPort)
	} else if *fwdDestination == "" {
		err = fmt.Errorf("flag destination is required")
	}
	if err != nil {
		log.Fatal(err)
	}

	// Initialize packet capture on vxlan0 interface
	log.Printf("starting capture on interface vxlan0")
	handle, err = pcap.OpenLive("vxlan0", 8951, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	// Set BPF filter to capture only TCP traffic on the specified port
	BPFFilter := fmt.Sprintf("tcp and dst port %d", *reqPort)
	if err := handle.SetBPFFilter(BPFFilter); err != nil {
		log.Fatal(err)
	}

	// Set up TCP stream assembly for HTTP request reconstruction
	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	log.Println("reading in packets")
	log.Printf("forwarding to: %s", *fwdDestination)
	if *tlsInsecure {
		log.Println("warning: TLS certificate verification is disabled")
	}
	
	// Create packet source and ticker for periodic cleanup
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)

	// Start TCP health check listener for AWS NLB
	go openTCPClient()

	// Main packet processing loop
	for {
		select {
		case packet := <-packets:
			// Handle end of packet stream
			if packet == nil {
				return
			}
			// Filter for valid TCP packets
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("unusable packet")
				continue
			}
			// Assemble TCP packets into streams for HTTP parsing
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			// Periodic cleanup of old TCP connections to prevent memory leaks
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -1))
		}
	}
}
