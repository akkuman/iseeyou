package portscan

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/akkuman/iseeyou/logger"
	"github.com/akkuman/iseeyou/pkg/cache"
	"github.com/akkuman/iseeyou/pkg/ifaces"
	"github.com/akkuman/iseeyou/pkg/options"
	"github.com/akkuman/iseeyou/pkg/util"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/phayes/freeport"
	"go.uber.org/ratelimit"
)

type State int

const (
	Scan State = iota
	Done
)

type IPPort struct {
	IP   net.IP
	Port uint16
}

func (p *IPPort) String() string {
	return fmt.Sprintf("%s:%d", p.IP.String(), p.Port)
}

var packetSerOpts = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

type Scanner struct {
	opt     *options.Options
	limiter ratelimit.Limiter
	// ipCache 保存已发送数据的
	ipCache    ifaces.ICache
	status     State
	pcapHandle *pcap.Handle
	srcIface   *net.Interface
	deviceName string
	srcIP      net.IP
	dstMac     net.HardwareAddr
	listenPort int
}

func NewScanner(opt *options.Options) *Scanner {
	var err error
	scanner := &Scanner{
		opt:     opt,
		// 缓存默认超时5分钟，代表syn包发出去后，如果五分钟内没有对应的ack，则会丢弃
		ipCache: cache.NewGoCache(),
	}
	rate := Band2Rate(opt.NetBandwidth)
	logger.Infof("发包速率: %dpps", rate)
	scanner.limiter = ratelimit.New(int(rate))
	scanner.srcIP, scanner.srcIface, err = GetLocalNetIface()
	if err != nil {
		logger.Fatalf("获取网卡接口失败: %v", err)
	}
	scanner.deviceName, err = GetDeviceName(scanner.srcIface)
	if err != nil {
		logger.Fatalf("获取网卡接口名称失败: %v", err)
	}
	logger.Infof("当前使用的网络接口: %s(%s)", scanner.srcIface.Name, scanner.deviceName)
	scanner.pcapHandle, err = pcap.OpenLive(scanner.deviceName, 65536, true, pcap.BlockForever)
	if err != nil {
		logger.Fatalf("打开网卡设备失败: %v", err)
	}
	scanner.dstMac, err = scanner.getHwAddr(*scanner.srcIface)
	if err != nil {
		logger.Fatalf("获取网关mac失败: %v", err)
	}
	scanner.listenPort, err = freeport.GetFreePort()
	if err != nil {
		logger.Fatalf("获取空闲端口失败: %v", err)
	}
	return scanner
}

func (s *Scanner) SetIPCache(c ifaces.ICache) {
	s.ipCache = c
}

// getHwAddr 获取网关mac地址（发送一个dns包，监听获取网关mac地址）
// ref: https://github.com/boy-hack/ksubdomain/blob/main/core/device/device.go#L15
func (s *Scanner) getHwAddr(srcIface net.Interface) (net.HardwareAddr, error) {
	domain := util.RandomStr(4) + ".baidu.com"
	signal := make(chan net.HardwareAddr)
	var e error
	go func() {
		for {
			data, _, err := s.pcapHandle.ReadPacketData()
			if err == pcap.NextErrorTimeoutExpired {
				continue
			} else if err != nil {
				signal <- nil
				e = err
			}
			packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
			if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				dns, _ := dnsLayer.(*layers.DNS)
				if !dns.QR {
					continue
				}
				for _, v := range dns.Questions {
					if string(v.Name) == domain {
						ethLayer := packet.Layer(layers.LayerTypeEthernet)
						if ethLayer != nil {
							eth := ethLayer.(*layers.Ethernet)
							signal <- eth.SrcMAC
							return
						}
					}
				}
			}
		}
	}()
	for {
		select {
		case c := <-signal:
			return c, e
		default:
			_, _ = net.LookupHost(domain)
			time.Sleep(time.Second * 1)
		}
	}
}

func (s *Scanner) Act(ctx context.Context, ipports <-chan interface{}) <-chan interface{} {
	s.status = Scan
	res := make(chan interface{}, 1024)
	go func() {
		for ipport := range ipports {
			v, ok := ipport.(*IPPort)
			if !ok {
				logger.Warnf("传入portscan.Act的数据类型并不是 *IPPort")
				continue
			}
			s.limiter.Take()
			s.writeSYN(ctx, v)
		}
		time.Sleep(DefaultWarmUpTime)
		s.status = Done
	}()
	go func() {
		defer close(res)
		err := s.recvAck(ctx, res)
		if err != nil {
			logger.Errorf("receive ack error: %v", err)
		}
	}()
	return res
}

// writeSYN 向指定的ip和port发送syn包
func (s *Scanner) writeSYN(ctx context.Context, ipport *IPPort) {
	// Construct all the network layers we need.
	eth := layers.Ethernet{
		SrcMAC:       s.srcIface.HardwareAddr,
		DstMAC:       s.dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    s.srcIP,
		DstIP:    ipport.IP.To4(),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(s.listenPort),
		DstPort: layers.TCPPort(ipport.Port), // will be incremented during the scan
		SYN:     true,
	}
	err := tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		logger.Warnf("checksum error: %v", err)
	}
	if err := s.send(&eth, &ip4, &tcp); err != nil {
		logger.Warnf("error sending to %v:%v: %v", ipport.IP.String(), tcp.DstPort, err)
		return
	}
	s.ipCache.Set(ipport.String(), struct{}{}, 0)
}

// send sends the given layers as a single packet on the network.
// ref: https://github.com/google/gopacket/blob/master/examples/synscan/main.go
func (s *Scanner) send(l ...gopacket.SerializableLayer) error {
	buf := gopacket.NewSerializeBuffer()

	if err := gopacket.SerializeLayers(buf, packetSerOpts, l...); err != nil {
		return err
	}
	return s.pcapHandle.WritePacketData(buf.Bytes())
}

func (s *Scanner) recvAck(ctx context.Context, resultChan chan<- interface{}) error {
	var snapshotLen = 65536
	var readtimeout = 1500
	inactive, err := pcap.NewInactiveHandle(s.deviceName)
	if err != nil {
		return err
	}
	defer inactive.CleanUp()

	err = inactive.SetSnapLen(snapshotLen)
	if err != nil {
		return err
	}

	readTimeout := time.Duration(readtimeout) * time.Millisecond
	if err = inactive.SetTimeout(readTimeout); err != nil {
		return err
	}
	err = inactive.SetImmediateMode(true)
	if err != nil {
		return err
	}

	handle, err := inactive.Activate()
	if err != nil {
		return err
	}
	defer handle.Close()
	// Strict BPF filter
	// + Packets coming from target ip
	// + Destination port equals to sender socket source port
	err = handle.SetBPFFilter(fmt.Sprintf("tcp and dst port %d and tcp[13]=18", s.listenPort))
	if err != nil {
		return err
	}

	// Listening
	var (
		eth layers.Ethernet
		ip4 layers.IPv4
		tcp layers.TCP
	)
	// Interfaces with MAC (Physical + Virtualized)
	parserMac := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp)
	// Interfaces without MAC (TUN/TAP)
	parserNoMac := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &tcp)

	var parsers []*gopacket.DecodingLayerParser
	parsers = append(parsers, parserMac, parserNoMac)

	decoded := []gopacket.LayerType{}

	for {
		if s.status == Done {
			break
		}
		// TODO: 需要考证会不会有几率卡死（结束后需要关闭handle？）
		data, _, err := handle.ReadPacketData()
		if err == io.EOF {
			break
		} else if err != nil {
			continue
		}

		for _, parser := range parsers {
			if err := parser.DecodeLayers(data, &decoded); err != nil {
				continue
			}
			for _, layerType := range decoded {
				if layerType == layers.LayerTypeTCP {
					ipport := fmt.Sprintf("%s:%d", ip4.SrcIP.String(), tcp.SrcPort)
					_, found := s.ipCache.Get(ipport)
					if !found {
						logger.Debugf("Discarding TCP packet from non target ip %s\n", ip4.SrcIP.String())
						continue
					}
					s.ipCache.Delete(ipport)

					// We consider only incoming packets
					if tcp.DstPort != layers.TCPPort(s.listenPort) {
						continue
					} else if tcp.SYN && tcp.ACK {
						logger.Infof("tcp://%v:%d open", ip4.SrcIP, tcp.SrcPort)
						resultChan <- &IPPort{IP: ip4.SrcIP, Port: uint16(tcp.SrcPort)}
					}
				}
			}
		}
	}
	return nil
}
