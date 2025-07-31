package main

import (
	"fmt"
	"github.com/orangehaired/TLSGhost/ghostbrowser/akamai"
	"log"
)

func main() {
	addr := "tls.peet.ws:443"
	sni := "tls.peet.ws"

	fp, err := akamai.FingerprintFromConn(addr, sni)
	if err != nil {
		log.Fatalf("Failed to extract fingerprint: %v", err)
	}

	fingerprint, hash := fp.AkamaiHash()

	fmt.Println("Akamai Fingerprint:", fingerprint)
	fmt.Println("Akamai MD5 Hash:", hash)
	fmt.Println("Check your real browser fingerprint at: https://tls.peet.ws")
	fmt.Printf("You can see this fingerprint hash: %s\n", hash)

	// My fingerprint hash is: 52d84b11737d980aef856699f885ca86
	// 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p (Chrome 137)
	// I also checked with Chrome canary. This hash is same.
}
