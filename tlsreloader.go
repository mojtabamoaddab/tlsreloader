package tlsreloader

import (
	"crypto/tls"
	"sync"
)

type TLSReloader struct {
	certPath string
	keyPath  string

	cert *tls.Certificate
	mu   sync.RWMutex
}

func New(certPath, keyPath string) (*TLSReloader, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	return &TLSReloader{
		certPath: certPath,
		keyPath:  keyPath,
		cert:     &cert,
	}, nil
}

func (tr *TLSReloader) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	return tr.cert, nil
}

func (tr *TLSReloader) Reload() error {
	cert, err := tls.LoadX509KeyPair(tr.certPath, tr.keyPath)
	if err != nil {
		return err
	}

	tr.mu.Lock()
	tr.cert = &cert
	tr.mu.Unlock()

	return nil
}
