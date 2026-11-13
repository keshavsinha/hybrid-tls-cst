package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9443", "")
	flag.Parse()
	cert, err := tls.LoadX509KeyPair("../cert.pem", "../key.pem")
	if err != nil {
		log.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	ln, err := tls.Listen("tcp", *addr, cfg)
	if err != nil {
		log.Fatal(err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			if err := c.(*tls.Conn).Handshake(); err != nil {
				log.Printf("hs: %v", err)
			}
		}(c)
	}
}
