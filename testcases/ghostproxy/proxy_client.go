package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

func main() {
	checkTlsPeet()
	checkBrowserLeak()

}

func checkTlsPeet() {
	proxyURL := "http://localhost:3129"

	ja3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,10-18-23-11-13-35-27-43-16-5-65281-45-17513-51-0,29-23-24,0"
	ua := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
	target := "https://tls.peet.ws/api/all"

	req, err := http.NewRequest("GET", proxyURL, nil)
	if err != nil {
		log.Fatalf("Request error: %v", err)
	}

	req.Header.Set("X-Target-URL", target)
	req.Header.Set("X-JA3-Hash", ja3)
	req.Header.Set("User-Agent", ua)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Proxy request failed: %v", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Read body failed: %v", err)
	}

	//fmt.Println("Response Status:", resp.Status)
	//fmt.Println("Response Body:")
	//fmt.Println(strings.Repeat("-", 80))
	//fmt.Println(string(body))

	var peetResp TLSPeetResponse
	if err := json.Unmarshal(body, &peetResp); err != nil {
		log.Fatalf("JSON decode failed: %v", err)
	}

	if peetResp.TLS.Ja3 == ja3 {
		log.Println("Match JA3 status with TLS Peet:", peetResp.TLS.Ja3 == ja3)
	}
}

type TLSPeetResponse struct {
	Donate      string `json:"donate"`
	IP          string `json:"ip"`
	HTTPVersion string `json:"http_version"`
	Method      string `json:"method"`
	UserAgent   string `json:"user_agent"`
	TLS         struct {
		Ciphers    []string `json:"ciphers"`
		Extensions []struct {
			Name       string   `json:"name"`
			Data       string   `json:"data,omitempty"`
			Protocols  []string `json:"protocols,omitempty"`
			Versions   []string `json:"versions,omitempty"`
			SharedKeys []struct {
				TLSGREASE0X2A2A    string `json:"TLS_GREASE (0x2a2a),omitempty"`
				X25519MLKEM7684588 string `json:"X25519MLKEM768 (4588),omitempty"`
				X2551929           string `json:"X25519 (29),omitempty"`
			} `json:"shared_keys,omitempty"`
			Algorithms      []string `json:"algorithms,omitempty"`
			SupportedGroups []string `json:"supported_groups,omitempty"`
			StatusRequest   struct {
				CertificateStatusType   string `json:"certificate_status_type"`
				ResponderIDListLength   int    `json:"responder_id_list_length"`
				RequestExtensionsLength int    `json:"request_extensions_length"`
			} `json:"status_request,omitempty"`
			ServerName                 string   `json:"server_name,omitempty"`
			MasterSecretData           string   `json:"master_secret_data,omitempty"`
			ExtendedMasterSecretData   string   `json:"extended_master_secret_data,omitempty"`
			PSKKeyExchangeMode         string   `json:"PSK_Key_Exchange_Mode,omitempty"`
			EllipticCurvesPointFormats []string `json:"elliptic_curves_point_formats,omitempty"`
			SignatureAlgorithms        []string `json:"signature_algorithms,omitempty"`
		} `json:"extensions"`
		TLSVersionRecord     string `json:"tls_version_record"`
		TLSVersionNegotiated string `json:"tls_version_negotiated"`
		Ja3                  string `json:"ja3"`
		Ja3Hash              string `json:"ja3_hash"`
		Ja4                  string `json:"ja4"`
		Ja4R                 string `json:"ja4_r"`
		Peetprint            string `json:"peetprint"`
		PeetprintHash        string `json:"peetprint_hash"`
		ClientRandom         string `json:"client_random"`
		SessionID            string `json:"session_id"`
	} `json:"tls"`
	HTTP2 struct {
		AkamaiFingerprint     string `json:"akamai_fingerprint"`
		AkamaiFingerprintHash string `json:"akamai_fingerprint_hash"`
		SentFrames            []struct {
			FrameType string   `json:"frame_type"`
			Length    int      `json:"length"`
			Settings  []string `json:"settings,omitempty"`
			Increment int      `json:"increment,omitempty"`
			StreamID  int      `json:"stream_id,omitempty"`
			Headers   []string `json:"headers,omitempty"`
			Flags     []string `json:"flags,omitempty"`
			Priority  struct {
				Weight    int `json:"weight"`
				DependsOn int `json:"depends_on"`
				Exclusive int `json:"exclusive"`
			} `json:"priority,omitempty"`
		} `json:"sent_frames"`
	} `json:"http2"`
	Tcpip struct {
		IP struct {
		} `json:"ip"`
		TCP struct {
		} `json:"tcp"`
	} `json:"tcpip"`
}

func checkBrowserLeak() {
	proxyURL := "http://localhost:3129"

	ja3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,10-18-23-11-13-35-27-43-16-5-65281-45-17513-51-0,29-23-24,0"
	ua := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
	target := "https://tls.browserleaks.com/json"

	req, err := http.NewRequest("GET", proxyURL, nil)
	if err != nil {
		log.Fatalf("Request error: %v", err)
	}

	req.Header.Set("X-Target-URL", target)
	req.Header.Set("X-JA3-Hash", ja3)
	req.Header.Set("User-Agent", ua)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Proxy request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Read body failed: %v", err)
	}

	fmt.Println("Response Status:", resp.Status)
	fmt.Println("Response Body:")
	fmt.Println(strings.Repeat("-", 80))
	fmt.Println(string(body))

	/*
		var leakResp BrowserLeakResponse
		if err := json.Unmarshal(body, &leakResp); err != nil {
			log.Fatalf("JSON decode failed: %v", err)
		}

		if leakResp.Ja3Text == ja3 {
			log.Println("Match JA3 status with Browser Leak:", leakResp.Ja3Text == ja3)
		}
	*/
}

type BrowserLeakResponse struct {
	UserAgent  string `json:"user_agent"`
	Ja3Hash    string `json:"ja3_hash"`
	Ja3Text    string `json:"ja3_text"`
	Ja3NHash   string `json:"ja3n_hash"`
	Ja3NText   string `json:"ja3n_text"`
	Ja4        string `json:"ja4"`
	Ja4R       string `json:"ja4_r"`
	Ja4O       string `json:"ja4_o"`
	Ja4Ro      string `json:"ja4_ro"`
	AkamaiHash string `json:"akamai_hash"`
	AkamaiText string `json:"akamai_text"`
}
