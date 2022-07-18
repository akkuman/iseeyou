package webx

import (
	"context"
	"fmt"

	"github.com/akkuman/iseeyou/logger"
	"github.com/akkuman/iseeyou/pkg/options"
	"github.com/akkuman/iseeyou/pkg/portscan"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/httpx/runner"
	"github.com/remeh/sizedwaitgroup"
)

type WebX struct {
	opt             *options.Options
	httpxRunner     *runner.Runner
	httpxRunnerOpts *runner.Options
}

func NewWebX(opt *options.Options) *WebX {
	var err error
	webx := new(WebX)
	webx.opt = opt
	webx.httpxRunnerOpts = &runner.Options{
		Methods:         "GET",
		Threads:         opt.WebXThreadCount,
		FollowRedirects: true,
		Retries:         0,
	}
	webx.httpxRunner, err = runner.New(webx.httpxRunnerOpts)
	if err != nil {
		logger.Fatalf("创建 httpx runner 失败: %v", err)
	}
	return webx
}

func (x *WebX) Act(ctx context.Context, targets <-chan interface{}) <-chan interface{} {
	wg := sizedwaitgroup.New(x.httpxRunnerOpts.Threads)
	scanopts := x.httpxRunner.GetScanOpts()
	runnerResultCh := make(chan runner.Result, 1000)
	resultChan := make(chan interface{}, 1000)
	go func() {
		defer close(runnerResultCh)
		for target := range targets {
			switch v := target.(type) {
			case *portscan.IPPort:
				u := fmt.Sprintf("%s:%d", v.IP.String(), v.Port)
				x.httpxRunner.Process(u, &wg, httpx.HTTPorHTTPS, &scanopts, runnerResultCh)
			default:
				logger.Warnf("webx.Act 传入未知类型 %T", target)
				continue
			}
		}
		wg.Wait()
	}()
	go func() {
		defer close(resultChan)
		for v := range runnerResultCh {
			if v.StatusCode == 0 {
				continue
			}
			logger.Infof("[%d] %s [%s]", v.StatusCode, v.URL, v.Title)
			resultChan <- v
		}
	}()
	return resultChan
}
