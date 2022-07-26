package webx

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"

	"github.com/twmb/murmur3"
)

// 和shodan相同的iconhash算法，来自https://github.com/Becivells/iconhash/blob/dev/config.go

// StandBase64 计算 base64 的值
func StandBase64(braw []byte) []byte {
	bckd := base64.StdEncoding.EncodeToString(braw)
	var buffer bytes.Buffer
	for i := 0; i < len(bckd); i++ {
		ch := bckd[i]
		buffer.WriteByte(ch)
		if (i+1)%76 == 0 {
			buffer.WriteByte('\n')
		}
	}
	buffer.WriteByte('\n')
	return buffer.Bytes()
}

func Mmh3Hash32(raw []byte) string {
	var h32 hash.Hash32 = murmur3.New32()
	h32.Write(raw)
	return fmt.Sprintf("%d", int32(h32.Sum32()))
}

func ShodanIconHash(content []byte) string {
	return Mmh3Hash32(StandBase64(content))
}

func MD5IconHash(content []byte) string {
	m := md5.New()
	m.Write(content)
	return hex.EncodeToString(m.Sum(nil))
}
