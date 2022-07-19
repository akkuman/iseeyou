package options

type Options struct {
	// 用户下行带宽
	NetBandwidth string
	// 获取web信息的线程数
	WebXThreadCount int
	ScanPorts string
	ExcludePorts string
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
