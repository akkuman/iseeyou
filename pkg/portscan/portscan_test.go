package portscan

import (
	"net"
	"testing"

	"github.com/akkuman/iseeyou/pkg/options"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var opt = options.Options{
	NetBandwidth: "2m",
}

func TestGetHwAddr(t *testing.T) {
	scanner := NewScanner(&opt)
	dstIface, err := scanner.getHwAddr()
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(dstIface)
}

func TestCalcSYNPacketLen(t *testing.T) {
	scanner := NewScanner(&opt)
	eth := layers.Ethernet{
		SrcMAC:       scanner.srcIface.HardwareAddr,
		DstMAC:       scanner.dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    scanner.srcIP,
		DstIP:    net.ParseIP("114.114.114.114").To4(),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(64897),
		DstPort: layers.TCPPort(53), // will be incremented during the scan
		SYN:     true,
		ACK: true,
	}
	tcp.SetNetworkLayerForChecksum(&ip4)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, packetSerOpts, &eth, &ip4, &tcp); err != nil {
		t.Error(err)
		return
	}
	t.Logf("SYN包长: %d", len(buf.Bytes()))
}