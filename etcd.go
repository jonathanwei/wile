package wile

import (
	"net/http"
	"path"
	"strings"
	"time"

	"golang.org/x/net/context"

	"github.com/golang/glog"
	"github.com/pkg/errors"
)

const etcdPrefix = "/wile/acme/http"

type etcdProvider struct {
	c *Client
}

func etcdKey(domain, token string) string {
	return path.Join(etcdPrefix, domain, token)
}

func (p etcdProvider) CleanUp(domain, token, keyAuth string) error {
	glog.Infof("Cleaning up %v, %v, %v", domain, token, keyAuth)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := p.c.etcd.Delete(ctx, etcdKey(domain, token))
	return errors.Wrap(err, "failed to delete from etcd")
}

func (p etcdProvider) Present(domain, token, keyAuth string) error {
	glog.Infof("Presenting %v, %v, %v", domain, token, keyAuth)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	etcd := p.c.etcd

	//const leaseDurationSeconds = 10 * 60 // 10 minutes in seconds
	//lease, err := etcd.Grant(ctx, leaseDurationSeconds)
	//if err != nil {
	//  return errors.Wrap(err, "failed to acquire lease")
	//}

	_, err := etcd.Put(ctx, etcdKey(domain, token), keyAuth /*, clientv3.WithLease(lease.ID)*/)
	return errors.Wrap(err, "failed to put into etcd")
}

func (c *Client) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	const acmePrefix = "/.well-known/acme-challenge/"
	if req.Method != "GET" || !strings.HasPrefix(req.URL.Path, acmePrefix) {
		http.NotFound(rw, req)
		return
	}

	key := etcdKey(req.Host, req.URL.Path[len(acmePrefix):])

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.etcd.Get(ctx, key)
	if err != nil {
		glog.Warningf("Failed to retrieve %v from etcd: %v", key, err)
		http.NotFound(rw, req)
		return
	}

	_, err = rw.Write(resp.Kvs[0].Value)
	if err != nil {
		glog.Warningf("Failed to write response: %v", err)
		return
	}
}
