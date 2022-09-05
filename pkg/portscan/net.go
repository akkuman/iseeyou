package portscan

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/akkuman/iseeyou/logger"
	"github.com/google/gopacket/pcap"
)

// GetInterfaceFromIP gets the name of the network interface from local ip address
// ref: https://github.com/projectdiscovery/naabu/blob/master/v2/pkg/scan/scan.go
func GetInterfaceFromIP(ip net.IP) (*net.Interface, error) {
	address := ip.String()

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, i := range interfaces {
		byNameInterface, err := net.InterfaceByName(i.Name)
		if err != nil {
			return nil, err
		}

		addresses, err := byNameInterface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, v := range addresses {
			// Check if the IP for the current interface is our
			// source IP. If yes, return the interface
			if strings.HasPrefix(v.String(), address+"/") {
				return byNameInterface, nil
			}
		}
	}

	return nil, fmt.Errorf("no interface found for ip %s", address)
}

// GetSourceIP gets the local ip based on our destination ip
// ref: https://github.com/projectdiscovery/naabu/blob/master/v2/pkg/scan/scan.go
func GetSourceIP(dstip net.IP) (net.IP, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip.String()+":12345")
	if err != nil {
		return nil, err
	}

	con, dialUpErr := net.DialUDP("udp", nil, serverAddr)
	if dialUpErr != nil {
		return nil, dialUpErr
	}

	defer con.Close()
	if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
		return udpaddr.IP, nil
	}

	return nil, nil
}

// GetSrcParameters gets the network parameters from the destination ip
// ref: https://github.com/projectdiscovery/naabu/blob/master/v2/pkg/scan/scan.go
func GetSrcParameters(destIP string) (srcIP net.IP, networkInterface *net.Interface, err error) {
	srcIP, err = GetSourceIP(net.ParseIP(destIP))
	if err != nil {
		return
	}

	networkInterface, err = GetInterfaceFromIP(srcIP)
	if err != nil {
		return
	}

	return
}

// GetLocalNetIface 获取本地网卡接口
func GetLocalNetIface() (srcIP net.IP, networkInterface *net.Interface, err error) {
	srcIP, networkInterface, err = GetSrcParameters(ExternalTargetForTune)
	return
}

// Band2Rate 将带宽转换为每秒发包速率
func Band2Rate(bandWith string) int64 {
	suffix := strings.ToLower(string(bandWith[len(bandWith)-1]))
	rate, _ := strconv.ParseInt(string(bandWith[0:len(bandWith)-1]), 10, 64)
	switch suffix {
	case "g":
		rate *= 1000000000
	case "m":
		rate *= 1000000
	case "k":
		rate *= 1000
	default:
		logger.Fatalf("unknown bandwith suffix '%s' (supported suffixes are G,M and K)\n", suffix)
	}
	packSize := int64(SYNPacketLen) // 一个DNS包大概有74byte
	rate = rate / packSize
	return rate
}

// GetDeviceName 获取网络接口名称（兼容windows）
// https://github.com/google/gopacket/issues/456
// https://github.com/codeyourweb/gopacket/blob/master/examples/arpscan/arpscan.go
func GetDeviceName(iface *net.Interface) (deviceName string, err error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}
	// We just look for IPv4 addresses, so try to find if the interface has one.
	var addr *net.IPNet
	if addrs, err := iface.Addrs(); err != nil {
		return "", err
	} else {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					addr = &net.IPNet{
						IP:   ip4,
						Mask: ipnet.Mask[len(ipnet.Mask)-4:],
					}
					break
				}
			}
		}
	}
	// Try to find a match between device and interface
	for _, d := range devices {
		if strings.Contains(fmt.Sprint(d.Addresses), fmt.Sprint(addr.IP)) {
			deviceName = d.Name
		}
	}
	if deviceName == "" {
		err = fmt.Errorf("cannot find the corresponding device for the interface %s", iface.Name)
	}
	return deviceName, err
}