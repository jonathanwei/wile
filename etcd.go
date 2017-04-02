package wile

import (
	"path"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/context"

	"github.com/coreos/etcd/clientv3"
	"github.com/pkg/errors"
)

type EtcdCache struct {
	etcd       *clientv3.Client
	etcdPrefix string
}

func NewEtcdCache(etcd *clientv3.Client, etcdPrefix string) *EtcdCache {
	return &EtcdCache{etcd, etcdPrefix}
}

func (e *EtcdCache) Get(ctx context.Context, key string) ([]byte, error) {
	gr, err := e.etcd.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if len(gr.Kvs) == 0 {
		return nil, autocert.ErrCacheMiss
	}
	return gr.Kvs[0].Value, nil
}

func (e *EtcdCache) Put(ctx context.Context, key string, data []byte) error {
	_, err := e.etcd.Put(ctx, e.etcdKey(key), string(data))
	return errors.Wrap(err, "failed to put into etcd")
}

func (e *EtcdCache) Delete(ctx context.Context, key string) error {
	_, err := e.etcd.Delete(ctx, e.etcdKey(key))
	return errors.Wrap(err, "failed to delete from etcd")
}

func (e *EtcdCache) etcdKey(key string) string {
	return path.Join(e.etcdPrefix, key)
}
