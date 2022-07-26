package options

import (
	"os"
	"path/filepath"

	"github.com/projectdiscovery/fileutil"
)

var (
	DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
	DefaultFingerprintHubJsonAddr = "https://raw.githubusercontent.com/0x727/FingerprintHub/main/web_fingerprint_v3.json"
	ConfigDir = ""
)

func GetCurPath() string {
	exePath, _ := os.Executable()
	path, _ := filepath.Abs(exePath)
	rst := filepath.Dir(path)
	return rst
}

func init() {
	dir := GetCurPath()
	ConfigDir = filepath.Join(dir, "./.config/iseeyou/")
	if !fileutil.FolderExists(ConfigDir) {
		os.MkdirAll(ConfigDir, 0777)
	}
}


type Options struct {
	// 用户下行带宽
	NetBandwidth string
	// 获取web信息的线程数
	WebXThreadCount int
	// 最大跟随跳转次数
	WebXMaxRedirects int
	WebXTimeout      int
	// 最大重试次数
	WebXRetryMax int
	// 请求web的最大速率每秒
	WebXRateLimit int
	ScanPorts     string
	ExcludePorts  string
	// inner
	scanPortList []uint16
}

func (o *Options) Init() error {
	return o.parseScanPorts()
}

func (o *Options) parseScanPorts() error {
	ports, err := ParsePorts(o)
	if err != nil {
		return err
	}
	uint16Ports := make([]uint16, len(ports))
	for i, port := range ports {
		uint16Ports[i] = uint16(port)
	}
	o.scanPortList = uint16Ports
	return nil
}

func (o *Options) GetScanPortList() []uint16 {
	return o.scanPortList
}
