package main

import (
	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	"github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
	"io"
	"log"
)

func main() {
	http.HandleFunc("/", handleProxy)
	log.Println("JA3 Spoof Proxy running on :3129")
	log.Fatal(http.ListenAndServe(":3129", nil))
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	targetURL := r.Header.Get("X-Target-URL")
	if targetURL == "" {
		http.Error(w, "Missing X-Target-URL header", http.StatusBadRequest)
		return
	}

	ja3 := r.Header.Get("X-JA3-Hash")
	userAgent := r.Header.Get("User-Agent")

	if ja3 == "" || userAgent == "" {
		http.Error(w, "Missing X-JA3-Hash or User-Agent header", http.StatusBadRequest)
		return
	}

	// Spec factory from JA3
	settings := map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	}
	settingsOrder := []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	}

	pseudoHeaderOrder := []string{
		":method",
		":authority",
		":scheme",
		":path",
	}

	connectionFlow := uint32(15663105)

	supportedSignatureAlgorithms := []string{
		"ECDSAWithP256AndSHA256",
		"PSSWithSHA256",
		"PKCS1WithSHA256",
		"ECDSAWithP384AndSHA384",
		"PSSWithSHA384",
		"PKCS1WithSHA384",
		"PSSWithSHA512",
		"PKCS1WithSHA512",
	}
	var supportedDelegatedCredentialsAlgorithms []string
	supportedVersions := []string{"GREASE", "1.3", "1.2"}
	keyShareCurves := []string{"GREASE", "X25519Kyber768", "X25519"}
	supportedProtocolsALPN := []string{"h2", "http/1.1"}
	supportedProtocolsALPS := []string{"h2"}
	echCandidateCipherSuites := []tls_client.CandidateCipherSuites{
		{
			KdfId:  "HKDF_SHA256",
			AeadId: "AEAD_AES_128_GCM",
		},
		{
			KdfId:  "HKDF_SHA256",
			AeadId: "AEAD_CHACHA20_POLY1305",
		},
	}
	candidatePayloads := []uint16{128, 160, 192, 224}
	certCompressionAlgos := []string{"brotli"}

	specFactory, err := tls_client.GetSpecFactoryFromJa3String(ja3, supportedSignatureAlgorithms, supportedDelegatedCredentialsAlgorithms, supportedVersions, keyShareCurves, supportedProtocolsALPN, supportedProtocolsALPS, echCandidateCipherSuites, candidatePayloads, certCompressionAlgos, 0)

	customClientProfile := profiles.NewClientProfile(tls.ClientHelloID{
		Client:      "TLSGhost",
		Version:     "1",
		Seed:        nil,
		SpecFactory: specFactory,
	}, settings, settingsOrder, pseudoHeaderOrder, connectionFlow, nil, nil)

	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(60),
		tls_client.WithClientProfile(customClientProfile),
	}

	client, err := tls_client.NewHttpClient(tls_client.NewDebugLogger(tls_client.NewLogger()), options...)
	if err != nil {
		log.Println(err)
		return
	}

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		log.Println(err)
		return
	}

	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return
	}

	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
