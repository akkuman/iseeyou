package targets

import (
	"context"
	"net"

	"github.com/akkuman/iseeyou/logger"
	"github.com/akkuman/iseeyou/pkg/options"
	"github.com/akkuman/iseeyou/pkg/portscan"
	"github.com/projectdiscovery/mapcidr"
)

type TargetBuilder struct {
	scanPortList []uint16
}

func NewTargetBuilder(opt *options.Options) *TargetBuilder {
	return &TargetBuilder{
		scanPortList: opt.GetScanPortList(),
	}
}

func (p *TargetBuilder) buildTargetList(ip net.IP) []*portscan.IPPort {
	var res []*portscan.IPPort
	for _, port := range p.scanPortList {
		res = append(res, &portscan.IPPort{
			IP:   ip,
			Port: port,
		})
	}
	return res
}

// Act 根据所给的ip返回所有的target
// inCh element support type: string of ip
func (p *TargetBuilder) Act(ctx context.Context, inCh <-chan interface{}) <-chan interface{} {
	outCh := make(chan interface{}, 1000)
	go func() {
		// TODO: 扫描端口超过100个则开启随机化
		// if len(p.scanPortList) >= 100 {
		// }
		defer close(outCh)
		for v := range inCh {
			switch vv := v.(type) {
			case string:
				var isIP, isCIDR bool
				var ipports []*portscan.IPPort
				if ip := net.ParseIP(vv); ip != nil {
					isIP = true
				} else if _, _, err := net.ParseCIDR(vv); err == nil {
					isCIDR = true
				}
				if !(isIP||isCIDR) {
					logger.Warnf("输入的数据不为ip或者cidr: %s", vv)
					continue
				}
				if isIP {
					ipports = append(ipports, p.buildTargetList(net.ParseIP(vv))...)
				} else if isCIDR {
					ipList, _ := mapcidr.IPAddresses(vv)
					for i := range ipList {
						ipports = append(ipports, p.buildTargetList(net.ParseIP(ipList[i]))...)
					}
				}
				for i := range ipports {
					outCh <- ipports[i]
				}
			default:
				logger.Warnf("webx.Act 传入未知类型 %T", v)
				continue
			}
		}
	}()
	return outCh
}
