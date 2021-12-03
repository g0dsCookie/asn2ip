package storage

import (
	"time"

	"github.com/sirupsen/logrus"
)

type memory struct {
	stor   map[string]ASStorage
	ttl    map[string]time.Time
	maxTTL time.Duration
}

func newMemory(opts StorageOptions) (Storage, error) {
	return &memory{
		stor:   map[string]ASStorage{},
		ttl:    map[string]time.Time{},
		maxTTL: opts.TTL,
	}, nil
}

func (m *memory) Get(as string) (ASStorage, error) {
	logrus.WithFields(logrus.Fields{"asn": as}).Debugln("trying to fetch asn from cache")
	v, ok := m.stor[as]
	if !ok {
		logrus.WithFields(logrus.Fields{"asn": as}).Debugln("cache missed for asn")
		return ASStorage{}, ErrASNotCached
	}
	ttl, ok := m.ttl[as]
	if !ok {
		logrus.WithFields(logrus.Fields{"asn": as}).Warnln("no ttl found for asn")
		delete(m.stor, as)
		return ASStorage{}, ErrASNotCached
	}
	if time.Since(ttl) > m.maxTTL {
		logrus.WithFields(logrus.Fields{"asn": as, "ttl": ttl}).Infoln("ttl expired for asn")
		delete(m.stor, as)
		delete(m.ttl, as)
		return ASStorage{}, ErrASNotCached
	}
	return v, nil
}

func (m *memory) Set(as ASStorage) error {
	m.stor[as.AS] = as
	m.ttl[as.AS] = time.Now()
	return nil
}
