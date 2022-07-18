package main

import (
	"context"
	"log"
	"net"
	"os"

	"github.com/akkuman/iseeyou/pkg/options"
	"github.com/akkuman/iseeyou/pkg/portscan"
	"github.com/akkuman/iseeyou/pkg/webx"
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
					&cli.IntFlag{
						Name: "webx-threads",
						Aliases: []string{"wt"},
						Usage: "获取web信息的线程数",
						Required: false,
						Value: 50,
					},
					// &cli.StringFlag{
					// 	Name:    "port",
					// 	Aliases: []string{"p"},
					// 	Usage:   "要扫描的端口",
					// 	Required: true,
					// },
				},
				Action: func(c *cli.Context) error {
					opt := options.Options{}
					cidr := c.String("cidr")
					opt.NetBandwidth = c.String("bandwidth")
					isWeb := c.Bool("web")
					opt.WebXThreadCount = c.Int("webx-threads")
					// port := c.String("port")
					ipports := make(chan interface{}, 100)
					go func() {
						defer close(ipports)
						for i := 0; i < 65535; i++ {
							ipports <- &portscan.IPPort{
								IP:   net.ParseIP(cidr).To4(),
								Port: uint16(i),
							}
						}
					}()
					ctx := context.Background()
					scanner := portscan.NewScanner(&opt)
					chIpPortWithTcpOpen := scanner.Act(ctx, ipports)
					if isWeb {
						webxClient := webx.NewWebX(&opt)
						webxResult := webxClient.Act(ctx, chIpPortWithTcpOpen)
						for range webxResult {}
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
