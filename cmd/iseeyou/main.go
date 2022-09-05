package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/akkuman/iseeyou/logger"
	"github.com/akkuman/iseeyou/pkg/options"
	"github.com/akkuman/iseeyou/pkg/portscan"
	"github.com/akkuman/iseeyou/pkg/targets"
	"github.com/akkuman/iseeyou/pkg/webx"
	"github.com/projectdiscovery/fileutil"
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
						Required: false,
						Value:    "",
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
						Name:     "webx-threads",
						Aliases:  []string{"wt"},
						Usage:    "获取web信息的线程数",
						Required: false,
						Value:    50,
					},
					&cli.IntFlag{
						Name:     "webx-timeout",
						Aliases:  []string{"wto"},
						Usage:    "获取web信息的超时时间",
						Required: false,
						Value:    5,
					},
					&cli.IntFlag{
						Name:     "webx-max-redirect",
						Aliases:  []string{"wmr"},
						Usage:    "获取web信息跟随跳转最大次数",
						Required: false,
						Value:    5,
					},
					&cli.IntFlag{
						Name:     "webx-retry-max",
						Aliases:  []string{"wrm"},
						Usage:    "获取web信息的最大重试次数",
						Required: false,
						Value:    0,
					},
					&cli.IntFlag{
						Name:     "webx-rate-limit",
						Aliases:  []string{"wrl"},
						Usage:    "获取web信息总体最大发包速率",
						Required: false,
						Value:    1000,
					},
					&cli.StringFlag{
						Name:     "ports",
						Aliases:  []string{"p"},
						Usage:    "要扫描的端口(支持 full, top100, top1000, 80,443, 100-200)",
						Required: false,
						Value:    "top100",
					},
				},
				Action: func(c *cli.Context) error {
					opt := &options.Options{}
					cidr := c.String("cidr")
					opt.NetBandwidth = c.String("bandwidth")
					isWeb := c.Bool("web")
					opt.WebXThreadCount = c.Int("webx-threads")
					opt.WebXTimeout = c.Int("webx-timeout")
					opt.WebXMaxRedirects = c.Int("webx-max-redirect")
					opt.WebXRetryMax = c.Int("webx-retry-max")
					opt.WebXRateLimit = c.Int("webx-rate-limit")
					opt.ScanPorts = c.String("ports")
					opt.Init()
					ctx := context.Background()

					targetBuilder := targets.NewTargetBuilder(opt)
					if cidr == "" && !fileutil.HasStdin() {
						logger.Fatalf("请正确输入目标")
					}
					cidrCh := make(chan interface{}, 100)
					go func() {
						defer close(cidrCh)
						if cidr != "" {
							cidrCh <- cidr
						} else if fileutil.HasStdin() {
							// 如果以管道形式传入
							scanner := bufio.NewScanner(os.Stdin)
							for scanner.Scan() {
								text := strings.TrimSpace(scanner.Text())
								if text != "" {
									cidrCh <- text
								}
							}
						}
					}()
					targetCh := targetBuilder.Act(ctx, cidrCh)

					scanner := portscan.NewScanner(opt)
					chIpPortWithTcpOpen := scanner.Act(ctx, targetCh)
					if isWeb {
						webxClient := webx.NewWebX(opt)
						webxResult := webxClient.Act(ctx, chIpPortWithTcpOpen)
						for r := range webxResult {
							switch v := r.(type) {
							case *webx.Response:
								fmt.Println(v.LogOutput)
							default:
								logger.Warnf("主流程传入未知类型 %T", r)
								continue
							} 
						}
					} else {
						for range chIpPortWithTcpOpen {}
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
