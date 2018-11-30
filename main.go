package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
)

func main() {
	cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Println(err)
		return
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cer}}

	ln, err := tls.Listen("tcp", ":https", tlsConfig)
	if err != nil {
		log.Fatalf("ssl listener %v", err)
	}
	defer ln.Close()
	tmp := make([]byte, 256)
	for {
		conn, err := ln.Accept()
		n, err := conn.Read(tmp)
		if err != nil {
			if err != io.EOF {
				fmt.Println("read error:", err)
			}
			continue
		}
		fmt.Println("rx:", string(tmp[:n]))
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
	log.Printf("%v\n", conn.LocalAddr())
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
