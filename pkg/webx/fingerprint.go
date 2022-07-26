package webx

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/akkuman/iseeyou/logger"
	"github.com/akkuman/iseeyou/pkg/options"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/retryablehttp-go"
)

var FingerPrints []FingerPrint

// from https://github.com/0x727/FingerprintHub

// FingerPrint 指纹结构体
type FingerPrint struct {
	Path           string            `json:"path"`
	RequestMethod  string            `json:"request_method"`
	RequestHeaders map[string]string `json:"request_headers"`
	RequestData    string            `json:"request_data"`
	StatusCode     int               `json:"status_code"`
	Headers        map[string]string `json:"headers"`
	Keyword        []string          `json:"keyword"`
	FaviconHash    []string          `json:"favicon_hash"`
	Priority       int               `json:"priority"`
	Name           string            `json:"name"`
}

// IsSpecial 是否为特殊指纹（非favicon和首页特征，需要自行发送请求的指纹）
func (f *FingerPrint) IsSpecial() bool {
	return f.Path != "/" || strings.ToLower(f.RequestMethod) != "get" || len(f.RequestHeaders) != 0 || len(f.RequestData) != 0
}

// HasFavicon 指纹是否包含favicon hash
func (f *FingerPrint) HasFavicon() bool {
	return len(f.FaviconHash) != 0
}

// HasRequestBody 指纹是否包含请求体
func (f *FingerPrint) HasRequestBody() bool {
	return len(f.RequestData) != 0
}

// IsBlank 判断指纹是否为空指纹
func (f *FingerPrint) IsBlank() bool {
	return f.StatusCode == 0 && len(f.Headers) == 0 && len(f.Keyword) == 0 && len(f.FaviconHash) == 0
}

// Match 匹配指纹判断是否命中, 注意resp的Body已经被Close
func (f *FingerPrint) Match(data []byte, resp *http.Response, respFavicons []Favicon) bool {
	// 匹配状态码
	if f.StatusCode != 0 && f.StatusCode != resp.StatusCode {
		return false
	}
	// 匹配header
	for k, v := range f.Headers {
		if _, ok := resp.Header[k]; !ok {
			return false
		}
		// *时只匹配键
		if v != "*" && v != resp.Header.Get(k) {
			return false
		}
	}
	// 匹配正文
	// 提前判断防止 []byte->string 的转化
	if len(f.Keyword) != 0 {
		bodytext := string(data)
		for _, keyword := range f.Keyword {
			if !strings.Contains(bodytext, keyword) {
				return false
			}
		}
	}
	// 匹配图标
	if f.HasFavicon() {
		matchFavicon := false
		// 存在favicon指纹的情况下，指纹中的iconhash没有一个匹配到，则指纹匹配失败
		for _, v1 := range respFavicons {
			for _, v2 := range f.FaviconHash {
				if v1.MD5 == v2 || v1.MMH3 == v2 {
					matchFavicon = true
				}
			}
		}
		if !matchFavicon {
			return false
		}
	}
	return true
}

func GetOnlineFingerprintData() ([]byte, error) {
	opts := retryablehttp.DefaultOptionsSpraying
	// opts := retryablehttp.DefaultOptionsSingle // use single options for single host
	client := retryablehttp.NewClient(opts)
	resp, err := client.Get(options.DefaultFingerprintHubJsonAddr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// GetFingerprintData 优先从本地获取指纹，如果本地没有，则从远程拉取指纹并保存到本地
func GetFingerprintData() ([]FingerPrint, error) {
	var err error
	fingerprints := make([]FingerPrint, 0)
	fingerprintFilepath := filepath.Join(options.ConfigDir, "./web_fingerprint_v3.json")
	var data []byte
	if fileutil.FileExists(fingerprintFilepath) {
		data, err = ioutil.ReadFile(fingerprintFilepath)
	} else {
		data, err = GetOnlineFingerprintData()
	}
	if err != nil {
		return nil, err
	}
	defer ioutil.WriteFile(fingerprintFilepath, data, 0644)
	err = json.Unmarshal(data, &fingerprints)
	if err != nil {
		return nil, err
	}
	return fingerprints, nil
}

// initFingerprint 初始化指纹，并去除空指纹
func initFingerprint() {
	var err error
	FingerPrints, err = GetFingerprintData()
	if err != nil {
		logger.Fatalf("获取指纹文件失败: %v", err)
	}
	normalCount := 0
	specialCount := 0
	var newFingerprints []FingerPrint
	for _, fingerprint := range FingerPrints {
		if fingerprint.IsBlank() {
			logger.Warnf("出现了web空指纹: %#v", fingerprint)
			continue
		}
		if fingerprint.IsSpecial() {
			specialCount += 1
		} else {
			normalCount += 1
		}
		newFingerprints = append(newFingerprints, fingerprint)
	}
	FingerPrints = newFingerprints
	logger.Infof("web 共有 %d 条常规指纹，%d 条特殊请求指纹", normalCount, specialCount)
}

func init() {
	initFingerprint()
}
