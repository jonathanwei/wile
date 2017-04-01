package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/golang/glog"
	"github.com/jonathanwei/wile"
	"github.com/unrolled/secure"
)

func run(backends map[string]*url.URL, hosts map[string]string, isDev bool, wileCfg *wile.Config) {
	wileClient, err := wile.NewClient(wileCfg)
	if err != nil {
		glog.Fatalf("Got error creating wile client: %v", err)
	}

	go httpServer(isDev, wileClient)
	httpsServer(backends, hosts, isDev, wileClient)
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

func httpsServer(backends map[string]*url.URL, hosts map[string]string, isDev bool, wileClient *wile.Client) {
	handler := newProxy(backends, hosts)
	server := &http.Server{
		Addr:    ":443",
		Handler: securify(isDev, handler),
		TLSConfig: &tls.Config{
			GetCertificate: wileClient.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		},
	}
	glog.Fatal(server.ListenAndServeTLS("", ""))
}

func httpServer(isDev bool, wileClient *wile.Client) {
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
	mux.Handle("/.well-known/acme-challenge/", wileClient)
	mux.Handle("/", securify(isDev, redirectHandler))

	glog.Fatal(http.ListenAndServe(":80", mux))
}

func securify(isDev bool, handler http.Handler) http.Handler {
	secureMiddleware := secure.New(secure.Options{
		STSSeconds:            60 * 60 * 24 * 365, // One year.
		STSIncludeSubdomains:  true,
		STSPreload:            true,
		FrameDeny:             true,
		ContentTypeNosniff:    true,
		BrowserXssFilter:      true,
		ContentSecurityPolicy: "default-src 'self'; object-src 'none'",
		IsDevelopment:         isDev,
	})
	return secureMiddleware.Handler(handler)
}
