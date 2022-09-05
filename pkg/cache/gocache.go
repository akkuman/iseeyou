package cache

import (
	"time"

	"github.com/patrickmn/go-cache"
)

type GoCache struct {
	c *cache.Cache
}

func NewGoCache() *GoCache {
	return &GoCache{
		c: cache.New(5*time.Minute, 5*time.Minute),
	}
}

func (gcache *GoCache) Get(k string) (v interface{}, found bool) {
	return gcache.c.Get(k)
}

func (gcache *GoCache) Set(k string, v interface{}, d time.Duration) {
	if d == 0 {
		d = cache.DefaultExpiration
	} else if d < 0  {
		d = cache.NoExpiration
	}
	gcache.c.Set(k, v, d)
}

func (gcache *GoCache) Delete(k string) {
	gcache.c.Delete(k)
}