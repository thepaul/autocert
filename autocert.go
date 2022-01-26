// Copyright (c) 2020-2022 by paul cannon <paul@thepaul.org> and Storj Labs, Inc
// Released under the terms of the Apache License version 2.0 (see the file LICENSE for details).

package autocert

import (
	"crypto/tls"
	"net"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

type HostPolicy = autocert.HostPolicy

// CertManager is a stateful certificate manager built on top of
// golang.org/x/crypto/acme/(*autocert.Manager), which is itself in turn built on top of
// golang.org/x/crypto/(*acme.Client). It obtains and refreshes certificates automatically using
// "tls-alpn-01" or "http-01" challenge types, as well as providing them to a TLS server via
// tls.Config.
type CertManager interface {
	Listen(network, address string) (net.Listener, error)
	TLSConfig() *tls.Config
}

type certManager struct {
	*autocert.Manager
}

// NewTLSAutoCertManager creates a new automatic certificate manager with the specified
// configuration items.
//
// hostPolicy determines which incoming connections will be accepted (see autocert.HostPolicy for
// more information).
//
// operatorEmail is the contact email address to be submitted to the ACME server, and which will be
// put into the issued SSL certificates.
//
// renewBefore specifies how early certificates should be renewed before they expire (e.g.,
// time.Hour * 24).
//
// cacheDir gives a directory which can be used as a certificate cache for storing SSL certificate
// information between invocations. If the directory does not exist, it will be created with 0700
// permissions.
func NewTLSAutoCertManager(hostPolicy autocert.HostPolicy, operatorEmail string, renewBefore time.Duration, cacheDir string) CertManager {
	autoManager := &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		Cache:       autocert.DirCache(cacheDir),
		HostPolicy:  hostPolicy,
		RenewBefore: renewBefore,
		Email:       operatorEmail,
	}
	return &certManager{autoManager}
}

type listener struct {
	m    *certManager
	conf *tls.Config

	tcpListener net.Listener
}

// Listen creates a new net.Listener which returns *tls.Conn connections.
//
// This is adapted from golang.org/x/crypto/acme/autocert listener.go, to allow binding to a
// different local port than 443. It is still necessary for the service to be externally accessible
// on port 443, for Let's-Encrypt to be able to contact it, but there may be port forwarding in
// between.
func (m *certManager) Listen(network, bindAddr string) (net.Listener, error) {
	ln := &listener{
		m:    m,
		conf: m.TLSConfig(),
	}
	var err error
	ln.tcpListener, err = net.Listen(network, bindAddr)
	if err != nil {
		return nil, err
	}
	return ln, nil
}

// Accept accepts a new TLS connection.
func (ln *listener) Accept() (net.Conn, error) {
	conn, err := ln.tcpListener.Accept()
	if err != nil {
		return nil, err
	}
	tcpConn := conn.(*net.TCPConn)

	_ = tcpConn.SetKeepAlive(true)
	_ = tcpConn.SetKeepAlivePeriod(3 * time.Minute)

	return tls.Server(tcpConn, ln.conf), nil
}

// Addr returns the address on which the listener is listening.
func (ln *listener) Addr() net.Addr {
	return ln.tcpListener.Addr()
}

// Close closes the listener.
func (ln *listener) Close() error {
	return ln.tcpListener.Close()
}
