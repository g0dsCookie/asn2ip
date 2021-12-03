package storage

import (
	"errors"
	"net"
	"time"
)

var (
	ErrASNotCached     = errors.New("as not in cache")
	ErrStorageNotFound = errors.New("storage type not found")
)

type storageFunc func(StorageOptions) (Storage, error)

var storages = map[string]storageFunc{
	"": newMemory, "default": newMemory, "memory": newMemory,
}

type ASStorage struct {
	AS          string
	IPv4        []*net.IPNet
	IPv6        []*net.IPNet
	FetchedIPv4 bool
	FetchedIPv6 bool
}

func (s ASStorage) IPAddresses() []*net.IPNet { return append(s.IPv4, s.IPv6...) }

type Storage interface {
	Get(as string) (ASStorage, error)
	Set(as ASStorage) error
}

type StorageOptions struct {
	Name string
	TTL  time.Duration
}

func NewStorage(opts StorageOptions) (Storage, error) {
	v, ok := storages[opts.Name]
	if !ok {
		return nil, ErrStorageNotFound
	}
	return v(opts)
}
