package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/golang/glog"
	"github.com/unrolled/secure"
	"golang.org/x/crypto/acme/autocert"
)

func run(backends map[string]*url.URL, hosts map[string]string, isDev bool, certMgr *autocert.Manager) {
	go httpServer(isDev, certMgr)
	httpsServer(backends, hosts, isDev, certMgr)
}

type proxy struct {
	handlers map[string]http.Handler
}

func newProxy(backends map[string]*url.URL, hosts map[string]string) *proxy {
	handlers := make(map[string]http.Handler)

	for host, backendName := range hosts {
		backendURL := backends[backendName]
		handlers[host] = httputil.NewSingleHostReverseProxy(backendURL)
	}

	return &proxy{
		handlers: handlers,
	}
}

func (p *proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	h, ok := p.handlers[req.Host]
	if !ok {
		glog.Infof("Got request for non-existent hostname %q", req.Host)
		http.NotFound(rw, req)
		return
	}

	h.ServeHTTP(rw, req)
}

func httpsServer(backends map[string]*url.URL, hosts map[string]string, isDev bool, certMgr *autocert.Manager) {
	handler := newProxy(backends, hosts)
	server := &http.Server{
		Addr:    ":443",
		Handler: securify(isDev, handler),
		TLSConfig: &tls.Config{
			GetCertificate: certMgr.GetCertificate,
			MinVersion:     tls.VersionTLS13,
		},
	}
	glog.Fatal(server.ListenAndServeTLS("", ""))
}

func httpServer(isDev bool, certMgr *autocert.Manager) {
	redirectHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		u := &url.URL{
			Scheme:   "https",
			Host:     req.Host,
			Path:     req.URL.Path,
			RawQuery: req.URL.RawQuery,
		}
		http.Redirect(rw, req, u.String(), http.StatusMovedPermanently)
	})

	mux := http.NewServeMux()
	mux.Handle("/", securify(isDev, redirectHandler))

	glog.Fatal(http.ListenAndServe(":80", certMgr.HTTPHandler(mux)))
}

func securify(isDev bool, handler http.Handler) http.Handler {
	secureMiddleware := secure.New(secure.Options{
		STSSeconds:            60 * 60 * 24 * 365, // One year.
		STSIncludeSubdomains:  true,
		STSPreload:            true,
		FrameDeny:             true,
		ContentTypeNosniff:    true,
		BrowserXssFilter:      true,
		ContentSecurityPolicy: "object-src 'none'; script-src $NONCE 'unsafe-inline' 'strict-dynamic' https:; base-uri 'none';",
		IsDevelopment:         isDev,
	})
	return secureMiddleware.Handler(handler)
}
