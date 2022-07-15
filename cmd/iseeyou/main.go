package main

import (
	"context"
	"log"
	"net"
	"os"

	"github.com/akkuman/iseeyou/logger"
	"github.com/akkuman/iseeyou/pkg/options"
	"github.com/akkuman/iseeyou/pkg/portscan"
	"github.com/dustin/go-broadcast"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "portscan",
				Usage: "端口扫描",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "cidr",
						Aliases:  []string{"r"},
						Usage:    "要扫描的CIDR",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "bandwidth",
						Aliases:  []string{"b"},
						Usage:    "预配置的下行带宽",
						Required: false,
						Value:    "2m",
					},
					&cli.BoolFlag{
						Name:     "web",
						Aliases:  []string{"w"},
						Usage:    "是否尝试获取web信息",
						Required: false,
						Value:    false,
					},
					// &cli.StringFlag{
					// 	Name:    "port",
					// 	Aliases: []string{"p"},
					// 	Usage:   "要扫描的端口",
					// 	Required: true,
					// },
				},
				Action: func(c *cli.Context) error {
					cidr := c.String("cidr")
					bandwidth := c.String("bandwidth")
					// port := c.String("port")
					ipports := make(chan *portscan.IPPort, 100)
					go func() {
						defer close(ipports)
						for i := 0; i < 65535; i++ {
							ipports <- &portscan.IPPort{
								IP:   net.ParseIP(cidr).To4(),
								Port: uint16(i),
							}
						}
					}()
					opt := options.Options{
						NetBandwidth: bandwidth,
					}
					scanner := portscan.NewScanner(opt)
					oChanIpPortWithTcpOpen := scanner.Act(context.Background(), ipports)
					// iChanwebInfo := make(chan *portscan.IPPort, 100)
					for ipport := range oChanIpPortWithTcpOpen {
						logger.Infof("%s:%d open", ipport.IP.String(), ipport.Port)
					}
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}


func workerHttpx(b broadcast.Broadcaster) {
	// ch := make(chan interface{})
	// b.Register(ch)
	// defer b.Unregister(ch)

	// options := runner.Options{
	// 	Methods:   "GET",
	// 	InputFile: inputFile,
	// }
	// httpxRunner, err := runner.New(&options)
}