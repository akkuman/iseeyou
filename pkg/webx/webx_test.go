package webx

import (
	"context"
	"net"
	"testing"

	"github.com/akkuman/iseeyou/pkg/options"
	"github.com/akkuman/iseeyou/pkg/portscan"
	"github.com/projectdiscovery/httpx/runner"
)

func TestWebXAct(t *testing.T) {
	opt := options.Options{
		WebXThreadCount: 50,
	}
	x, err := NewWebX(&opt)
	if err != nil {
		t.Error(err)
		return
	}
	inCh := make(chan interface{}, 10)
	inCh <- portscan.IPPort{
		IP: net.ParseIP("96.43.94.90"),
		Port: 8081,
	}
	close(inCh)
	outCh := x.Act(context.Background(), inCh)
	for v := range outCh {
		vv := v.(runner.Result)
		t.Logf("%#v", vv)
	}
}
