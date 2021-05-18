package main

import (
	"crypto/tls"
	"crypto/x509"
	"os"

	_ "embed"

	"github.com/elazarl/goproxy"
)

//go:embed certs/ca.pem
var caCert []byte

//go:embed certs/ca.key.pem
var caKey []byte

func setCA() error {
	goproxyCa, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return err
	}
	if goproxyCa.Leaf, err = x509.ParseCertificate(goproxyCa.Certificate[0]); err != nil {
		return err
	}
	goproxy.GoproxyCa = goproxyCa
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	return nil
}

func writeCA(certFile string) error {
	f, err := os.Create(certFile)
	if err != nil {
		return err
	}

	defer f.Close()

	if _, err := f.Write([]byte(caKey)); err != nil {
		return err
	}
	if _, err := f.Write([]byte("\n")); err != nil {
		return err
	}
	if _, err := f.Write([]byte(caCert)); err != nil {
		return err
	}

	return nil
}
