package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"crypto/rand"
	"crypto/tls"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
)

func main() {
	var cache autocert.Cache = autocert.DirCache("certs")
	m := autocert.Manager{
		Cache:      cache,
		Prompt:     autocert.AcceptTOS,
		HostPolicy: nil,
		Email:      "doracl1@gmail.com",
	}
	getCertificate := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		res, err := m.GetCertificate(hello)
		log.Printf("Getting cert for %s", hello.ServerName)
		if err != nil {
			log.Print("GetCertificate debug: ", err)
		}
		return res, err
	}
	tlsConfig := &tls.Config{
		Rand:           rand.Reader,
		Time:           time.Now,
		NextProtos:     []string{http2.NextProtoTLS, "http/1.1"},
		MinVersion:     tls.VersionTLS12,
		GetCertificate: getCertificate,
	}

	ln, err := tls.Listen("tcp", ":https", tlsConfig)
	if err != nil {
		log.Fatalf("ssl listener %v", err)
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go forward("192.168.0.153:80", conn, false)
	}
}

func split(addr net.Addr) (string, string, error) {
	tmp := strings.Split(addr.String(), ":")
	ip := net.ParseIP(tmp[0]).To4()
	if ip == nil {
		return "", "", fmt.Errorf("source address %s is not a tcp4 IP", tmp[0])
	}
	return ip.String(), tmp[1], nil
}

func forward(backendHostport string, conn net.Conn, proxyproto bool) {
	backend, err := net.Dial("tcp", backendHostport)
	if err != nil {
		log.Printf("Dial failed: %v", err)
		conn.Close()
		return
	}
	if proxyproto {
		tcpversion := "TCP4"
		srcaddr, srcport, srcerr := split(conn.RemoteAddr())
		dstaddr, dstport, _ := split(conn.LocalAddr())
		if srcerr != nil { // source address is not tcp4
			log.Print("address is not TCPv4 ", conn.RemoteAddr())
			conn.Close()
			return
		}
		proxyheader := fmt.Sprintf("PROXY %s %s %s %s %s\r\n", tcpversion, srcaddr, dstaddr, srcport, dstport)
		backend.Write([]byte(proxyheader))
	}
	go func() {
		defer backend.Close()
		defer conn.Close()
		io.Copy(backend, conn)
	}()
	go func() {
		defer backend.Close()
		defer conn.Close()
		io.Copy(conn, backend)
	}()
}
