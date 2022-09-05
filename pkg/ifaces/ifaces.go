package ifaces

import "time"

type ICache interface {
	// Set 设置值，如果d==0，则设置为默认超时，如果d<0，则不设置超时
	Set(k string, v interface{}, d time.Duration)
	Get(k string) (v interface{}, found bool)
	Delete(k string)
}