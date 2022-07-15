package portscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/akkuman/iseeyou/logger"
	"github.com/akkuman/iseeyou/pkg/cache"
	"github.com/akkuman/iseeyou/pkg/ifaces"
	"github.com/akkuman/iseeyou/pkg/options"
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

var packetSerOpts = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

type Scanner struct {
	opt     options.Options
	limiter ratelimit.Limiter
	// ipCache 保存已发送数据的
	ipCache    ifaces.ICache
	status     State
	pcapHandle *pcap.Handle
	srcIface   *net.Interface
	srcIP      net.IP
	dstMac     net.HardwareAddr
	listenPort int
}

func NewScanner(opt options.Options) *Scanner {
	var err error
	scanner := &Scanner{
		opt:     opt,
		ipCache: cache.NewGoCache(),
	}
	rate := Band2Rate(opt.NetBandwidth)
	logger.Infof("发包速率: %dpps", rate)
	scanner.limiter = ratelimit.New(int(rate))
	scanner.srcIP, scanner.srcIface, err = GetLocalNetIface()
	if err != nil {
		logger.Fatalf("获取网卡接口失败: %v", err)
	}
	scanner.pcapHandle, err = pcap.OpenLive(scanner.srcIface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		logger.Fatalf("打开网卡设备失败: %v", err)
	}
	scanner.dstMac, err = scanner.getHwAddr()
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

// getHwAddr is a hacky but effective way to get the destination hardware
// address for our packets.  It does an ARP request for our gateway (if there is
// one) or destination IP (if no gateway is necessary), then waits for an ARP
// reply.  This is pretty slow right now, since it blocks on the ARP
// request/reply.
// ref: https://github.com/google/gopacket/blob/master/examples/synscan/main.go
func (s *Scanner) getHwAddr() (net.HardwareAddr, error) {
	start := time.Now()
	iface := s.srcIface
	src := s.srcIP
	arpDst := net.ParseIP(ExternalTargetForTune).To4()

	// Prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(src),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(arpDst),
	}
	// Send a single ARP request packet (we never retry a send, since this
	// is just an example ;)
	if err := s.send(&eth, &arp); err != nil {
		return nil, err
	}
	// Wait 3 seconds for an ARP reply.
	for {
		if time.Since(start) > time.Second*3 {
			return nil, errors.New("timeout getting ARP reply")
		}
		data, _, err := s.pcapHandle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return nil, err
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if net.IP(arp.SourceProtAddress).Equal(net.IP(arpDst)) {
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		}
	}
}

func (s *Scanner) Act(ctx context.Context, ipports <-chan *IPPort) <-chan *IPPort {
	s.status = Scan
	res := make(chan *IPPort, 1024)
	go func() {
		for ipport := range ipports {
			s.limiter.Take()
			s.writeSYN(ctx, ipport)
		}
		time.Sleep(DefaultWarmUpTime)
		s.status = Done
	}()
	go func() {
		defer close(res)
		s.recvAck(ctx, res)
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
		DstIP:    ipport.IP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(s.listenPort),
		DstPort: layers.TCPPort(ipport.Port), // will be incremented during the scan
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(&ip4)
	if err := s.send(&eth, &ip4, &tcp); err != nil {
		logger.Warnf("error sending to port %v: %v", tcp.DstPort, err)
		return
	}
	s.ipCache.Set(ipport.IP.String(), struct{}{}, -1)
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

func (s *Scanner) recvAck(ctx context.Context, resultChan chan<- *IPPort) error {
	var snapshotLen = 65536
	var readtimeout = 1500
	inactive, err := pcap.NewInactiveHandle(s.srcIface.Name)
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
					_, found := s.ipCache.Get(ip4.SrcIP.String())
					if !found {
						logger.Debugf("Discarding TCP packet from non target ip %s\n", ip4.SrcIP.String())
						continue
					}

					// We consider only incoming packets
					if tcp.DstPort != layers.TCPPort(s.listenPort) {
						continue
					} else if tcp.SYN && tcp.ACK {
						resultChan <- &IPPort{IP: ip4.SrcIP, Port: uint16(tcp.SrcPort)}
					}
				}
			}
		}
	}
	return nil
}
