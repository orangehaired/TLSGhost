package akamai

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"golang.org/x/net/http2"
	"io"
	"net"
	"strings"
	"time"
)

// Fingerprint represents the HTTP/2 fingerprint extracted from a connection as like Akamai's TLS fingerprinting.
type Fingerprint struct {
	SettingsKeys      []http2.SettingID
	SettingsValues    map[http2.SettingID]uint32
	InitialFrameTypes []string
}

// FingerprintFromConn
// Referenced: https://github.com/pagpeter/TrackMe/blob/master/fingerprint_h2.go#L15
func FingerprintFromConn(address, sni string) (*Fingerprint, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tcpConn, err := dialer.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("TCP dial failed: %w", err)
	}
	tlsConn := tls.Client(tcpConn, &tls.Config{
		ServerName:         sni,
		NextProtos:         []string{"h2"},
		InsecureSkipVerify: true,
	})
	err = tlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	h2Framer := http2.NewFramer(io.Discard, tlsConn)

	if _, err := tlsConn.Write([]byte(http2.ClientPreface)); err != nil {
		return nil, fmt.Errorf("failed to send preface: %w", err)
	}

	// Send SETTINGS frame
	settings := []http2.Setting{
		{ID: http2.SettingHeaderTableSize, Val: 65536},
		{ID: http2.SettingMaxConcurrentStreams, Val: 1000},
		{ID: http2.SettingInitialWindowSize, Val: 6291456},
		{ID: http2.SettingMaxFrameSize, Val: 16384},
	}
	if err := h2Framer.WriteSettings(settings...); err != nil {
		return nil, fmt.Errorf("failed to write settings: %w", err)
	}

	fp := &Fingerprint{
		SettingsKeys:      []http2.SettingID{},
		SettingsValues:    map[http2.SettingID]uint32{},
		InitialFrameTypes: []string{},
	}

	for _, s := range settings {
		fp.SettingsKeys = append(fp.SettingsKeys, s.ID)
		fp.SettingsValues[s.ID] = s.Val
	}
	
	fp.InitialFrameTypes = append(fp.InitialFrameTypes, "SETTINGS")

	return fp, nil
}

// AkamaiHash returns the Akamai-style fingerprint hash (MD5 of formatted string) on: https://tls.peet.ws
func (fp *Fingerprint) AkamaiHash() (string, string) {
	var keys []string
	var values []string
	for _, k := range fp.SettingsKeys {
		keys = append(keys, fmt.Sprintf("%d", k))
		values = append(values, fmt.Sprintf("%d", fp.SettingsValues[k]))
	}

	keyStr := strings.Join(keys, "-")
	valStr := strings.Join(values, ",")
	frameStr := strings.Join(fp.InitialFrameTypes, ",")

	combined := keyStr + "|" + valStr + "|" + frameStr
	hash := md5.Sum([]byte(combined))
	return combined, hex.EncodeToString(hash[:])
}
