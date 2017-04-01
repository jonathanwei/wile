package wile

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"github.com/xenolf/lego/acme"
)

type Config struct {
	// Endpoint for ACME protocol.
	APIEndpoint string

	// The email used for registration.
	Email string

	// Path to save persistent state in between program runs.
	Path string

	// Initial list of domains to obtain certs for.
	InitialDomains []string

	EtcdEndpoints []string
}

func NewClient(cfg *Config) (*Client, error) {
	c := &Client{cfg: cfg}

	err := c.init()
	if err != nil {
		return nil, err
	}

	return c, nil
}

type Client struct {
	cfg    *Config
	client *acme.Client
	etcd   *clientv3.Client

	certMu   sync.Mutex   // used by writers of certs.
	certs    atomic.Value // stores a certMap
	acmeCert map[string]string

	dataMu sync.Mutex
	dataCh chan bool
	data   *data

	tickCh chan bool

	domainsMu sync.Mutex
	domains   []string
}

type certMap map[string]*tls.Certificate

func (c *Client) SetDomains(domains []string) {
	c.domainsMu.Lock()
	defer c.domainsMu.Unlock()

	// Take a defensive copy to avoid concurrent modification.
	c.domains = append([]string(nil), domains...)

	// Wake up domainLoop.
	select {
	case c.tickCh <- true:
	default:
	}
}

func (c *Client) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	certs := c.certs.Load().(certMap)

	cert, ok := certs[clientHello.ServerName]
	if !ok {
		return nil, fmt.Errorf("Unknown server name: %v", clientHello.ServerName)
	}

	return cert, nil
}

func (c *Client) domainLoop() {
	for range c.tickCh {
		c.domainsMu.Lock()
		domains := c.domains
		c.domainsMu.Unlock()

		for _, domain := range domains {
			certs := c.certs.Load().(certMap)
			cert, hasExisting := certs[domain]

			// If we don't have any certs for this domain, then fetch one.
			if !hasExisting {
				c.createCert(domain)
				continue
			}

			// If we have a cert and it is valid for more than 30 days, then just check
			// again later.
			valid := cert.Leaf.NotAfter.Sub(time.Now())
			if valid > 30*24*time.Hour {
				glog.Infof("Certificate for %q is still valid for %v.", domain, valid)
				continue
			}

			// If we have a cert, and it needs renewal, then go ahead and do that.
			c.renewCert(domain)
		}
	}
}

func (c *Client) createCert(domain string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		glog.Errorf("Got error generating ecdsa key: %v", err)
		return
	}

	certResource, errs := c.client.ObtainCertificate([]string{domain}, true, key, false)
	// TODO: handle TOSError.
	if len(errs) > 0 {
		glog.Errorf("Got error when trying to obtain certificates: %v", errs)
		return
	}
	c.acceptNewCertResource(domain, certResource)
	glog.Infof("Acquired cert for %q.", domain)
}

func (c *Client) renewCert(domain string) {
	c.dataMu.Lock()
	jcr, ok := c.data.Certs[domain]
	c.dataMu.Unlock()

	if !ok {
		// Trying to renew a cert that doesn't exist?
		panic("consistency error")
	}

	// jcr explicitly drops these fields from its JSON representation so we copy
	// them from our representation.
	jcr.CertResource.Certificate = jcr.Certificate
	jcr.CertResource.PrivateKey = jcr.PrivateKey

	certResource, err := c.client.RenewCertificate(jcr.CertResource, true, false)
	if err != nil {
		glog.Errorf("Got error renewing cert: %v", err)
		return
	}

	c.acceptNewCertResource(domain, certResource)
	glog.Infof("Renewed cert for %q.", domain)
}

func (c *Client) acceptNewCertResource(domain string, certResource acme.CertificateResource) {
	cert, err := tls.X509KeyPair(certResource.Certificate, certResource.PrivateKey)
	if err != nil {
		glog.Errorf("Got error when parsing cert: %v", err)
		return
	}

	err = setLeaf(&cert)
	if err != nil {
		glog.Errorf("Got error when setting leaf cert: %v", err)
		return
	}

	c.mutateCerts(func(certs certMap) {
		certs[domain] = &cert
	})

	c.mutateData(func(d *data) {
		d.Certs[domain] = jsonCertResource{
			CertResource: certResource,
			Certificate:  certResource.Certificate,
			PrivateKey:   certResource.PrivateKey,
		}
	})
}

func (c *Client) init() error {
	etcd, err := clientv3.New(clientv3.Config{
		Endpoints:   c.cfg.EtcdEndpoints,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return errors.Wrap(err, "failed to init etcd")
	}
	c.etcd = etcd

	d, err := c.readData()
	if err != nil {
		return err
	}

	c.client, err = acme.NewClient(c.cfg.APIEndpoint, d, acme.EC256)
	if err != nil {
		return err
	}

	if d.Reg == nil {
		d.Reg, err = c.client.Register()
		if err != nil {
			return err
		}

		err = c.client.AgreeToTOS()
		if err != nil {
			return err
		}
	}

	c.data = d
	c.dataCh = make(chan bool, 1)
	c.dataCh <- true

	go c.dataWriter()

	c.client.ExcludeChallenges([]acme.Challenge{acme.DNS01, acme.TLSSNI01})
	c.client.SetChallengeProvider(acme.HTTP01, etcdProvider{c})

	// Setup initial certificates.
	initialCerts := make(certMap)
	for _, domain := range c.cfg.InitialDomains {
		certResource, ok := d.Certs[domain]
		if !ok {
			continue
		}

		cert, err := tls.X509KeyPair(certResource.Certificate, certResource.PrivateKey)
		if err != nil || setLeaf(&cert) != nil {
			// We couldn't parse the cert from disk, but it's fine, we'll just obtain
			// a new one.
			continue
		}

		initialCerts[domain] = &cert
	}

	c.certs.Store(initialCerts)
	c.acmeCert = make(map[string]string)

	c.tickCh = make(chan bool, 1)
	go c.tick()

	c.SetDomains(c.cfg.InitialDomains)

	go c.domainLoop()

	return nil
}

func (c *Client) tick() {
	// TODO: Support graceful shutdown.
	tick := time.Tick(10 * time.Minute)
	for range tick {
		select {
		case c.tickCh <- true:
		default:
			// Do nothing if the buffer is full.
		}
	}
}

func (c *Client) readData() (*data, error) {
	f, err := os.Open(c.cfg.Path)
	if os.IsNotExist(err) {
		return c.initData()
	} else if err != nil {
		return nil, err
	}

	dec := json.NewDecoder(f)

	var d data
	err = d.DecodeFromJSON(dec)
	if err != nil {
		return nil, fmt.Errorf("Couldn't decode existing file as JSON: %v", err)
	}

	return &d, nil
}

func (c *Client) dataWriter() {
	for {
		// TODO: handle graceful shutdown.
		<-c.dataCh

		err := c.writeDataJSON()
		if err != nil {
			glog.Errorf("Couldn't write data file: %v", err)
			go c.delayedDataWrite()
		}
	}
}

func (c *Client) writeDataJSON() error {
	var (
		j   []byte
		err error
	)

	func() {
		c.dataMu.Lock()
		defer c.dataMu.Unlock()
		j, err = json.MarshalIndent(c.data, "", "  ")
	}()

	if err != nil {
		return err
	}

	f, err := ioutil.TempFile(filepath.Dir(c.cfg.Path), "")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())

	_, err = f.Write(j)
	if err != nil {
		return err
	}

	err = f.Close()
	if err != nil {
		return err
	}

	return os.Rename(f.Name(), c.cfg.Path)
}

// Mark data as requiring write-back after a short delay. Intended to be used
// when handling errors writing the data file to disk.
func (c *Client) delayedDataWrite() {
	// TODO: support graceful shutdown.
	time.Sleep(5 * time.Minute)
	c.mutateData(func(d *data) {})
}

func (c *Client) initData() (*data, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	d := &data{
		Email:      c.cfg.Email,
		PrivateKey: x509.MarshalPKCS1PrivateKey(privateKey),
		privateKey: privateKey,
		Certs:      make(map[string]jsonCertResource),
	}

	return d, nil
}

func setLeaf(cert *tls.Certificate) error {
	x509cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}

	cert.Leaf = x509cert
	return nil
}

func (c *Client) mutateData(mutate func(d *data)) {
	c.dataMu.Lock()
	defer c.dataMu.Unlock()

	mutate(c.data)

	select {
	case c.dataCh <- true:
	default:
	}
}

func (c *Client) mutateCerts(mutate func(c certMap)) {
	c.certMu.Lock()
	defer c.certMu.Unlock()

	oldCerts := c.certs.Load().(certMap)

	// Clone.
	newCerts := make(certMap)
	for k, v := range oldCerts {
		newCerts[k] = v
	}

	mutate(newCerts)

	c.certs.Store(newCerts)
}

type jsonCertResource struct {
	CertResource acme.CertificateResource
	Certificate  []byte `json:"certificate"`
	PrivateKey   []byte `json:"privateKey"`
}

type data struct {
	Email string                     `json:"email"`
	Reg   *acme.RegistrationResource `json:"reg"`

	PrivateKey []byte `json:"privateKey"`
	privateKey *rsa.PrivateKey

	// Existing certs.
	Certs map[string]jsonCertResource `json:"certs"`
}

func (d *data) GetEmail() string {
	return d.Email
}

func (d *data) GetRegistration() *acme.RegistrationResource {
	return d.Reg
}

func (d *data) GetPrivateKey() crypto.PrivateKey {
	return d.privateKey
}

func (d *data) DecodeFromJSON(dec *json.Decoder) error {
	err := dec.Decode(d)
	if err != nil {
		return err
	}

	if d.PrivateKey != nil {
		d.privateKey, err = x509.ParsePKCS1PrivateKey(d.PrivateKey)
		if err != nil {
			return err
		}
	}

	if d.Certs == nil {
		d.Certs = make(map[string]jsonCertResource)
	}

	return nil
}
