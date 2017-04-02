package main

import (
	"flag"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/jonathanwei/wile"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	var (
		backendsFlag = flag.String("backends", "", "Comma-separated list of backends. Each backend is of the form <short-name>:<url>")
		hostsFlag    = flag.String("hosts", "", "Comma-separated list of hosts to serve and their correspondin backend. Each host is of the form <host>:<backend>")
		development  = flag.Bool("insecure_development_mode", false, "True iff the server should run in an insecure development mode.")
		acmeEndpoint = flag.String("acme", "https://acme-staging.api.letsencrypt.org/directory", "The ACME server to sign certs.")
		acmeEmail    = flag.String("email", "", "The email to use when registering with acme.")
		certKey      = flag.String("cert_key", "", "The key to encrypt certificates in etcd.")
	)

	flag.Parse()

	if *certKey == "" {
		log.Fatal("Must provide -cert_key")
	}

	backends := parseBackendSpecs(*backendsFlag)
	hosts := parseHostSpecs(*hostsFlag, backends)

	var domains []string
	for h := range hosts {
		domains = append(domains, h)
	}

	etcd, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"localhost:2378"},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		log.Fatalf("Failed to connect to etcd: %v", err)
	}

	cache, err := wile.NewEncryptingCache(wile.NewEtcdCache(etcd, "/wile/acme/http"), []byte(*certKey))
	if err != nil {
		log.Fatalf("Failed to create cache: %v", err)
	}

	m := autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		Cache:       cache,
		HostPolicy:  autocert.HostWhitelist(domains...),
		RenewBefore: 30 * 24 * time.Hour,
		Client:      &acme.Client{DirectoryURL: *acmeEndpoint},
		Email:       *acmeEmail,
	}

	run(backends, hosts, *development, &m)
}

func parseBackendSpecs(specs string) map[string]*url.URL {
	backends := make(map[string]*url.URL)
	for _, spec := range strings.Split(specs, ",") {
		fatal := func(msg string) {
			log.Fatalf("Invalid backend spec %q, %s", spec, msg)
		}

		idx := strings.Index(spec, ":")
		if idx == -1 {
			fatal("missing ':'")
		}

		name := spec[:idx]
		ustr := spec[idx+1:]

		if len(name) == 0 {
			fatal("empty name not allowed")
		}

		if len(ustr) == 0 {
			fatal("empty url not allowed")
		}

		if _, ok := backends[name]; ok {
			fatal("duplicate backend name")
		}

		u, err := url.Parse(ustr)
		if err != nil {
			fatal(fmt.Sprintf("couldn't parse url: %v", err))
		}

		backends[name] = u
	}

	return backends
}

func parseHostSpecs(specs string, backends map[string]*url.URL) map[string]string {
	hosts := make(map[string]string)
	for _, spec := range strings.Split(specs, ",") {
		fatal := func(msg string) {
			log.Fatalf("Invalid host spec %q, %s", spec, msg)
		}

		idx := strings.Index(spec, ":")
		if idx == -1 {
			fatal("missing ':'")
		}

		host := spec[:idx]
		backend := spec[idx+1:]

		if len(host) == 0 {
			fatal("empty host not allowed")
		}

		if _, ok := hosts[host]; ok {
			fatal("duplicate host not allowed")
		}

		if _, ok := backends[backend]; !ok {
			fatal("unknown backend")
		}

		hosts[host] = backend
	}

	return hosts
}
