package webx

import (
	"context"
	"net"
	"testing"

	"github.com/akkuman/iseeyou/pkg/options"
	"github.com/akkuman/iseeyou/pkg/portscan"
	"github.com/projectdiscovery/httpx/runner"
)

// go test -v ./pkg/webx/ -test.run TestWebXAct
func TestWebXAct(t *testing.T) {
	opt := options.Options{
		WebXThreadCount: 50,
	}
	x := NewWebX(&opt)
	inCh := make(chan interface{}, 10)
	inCh <- &portscan.IPPort{
		IP: net.ParseIP("36.112.99.182"),
		Port: 39443,
	}
	close(inCh)
	outCh := x.Act(context.Background(), inCh)
	for v := range outCh {
		vv := v.(runner.Result)
		t.Logf("%#v", vv)
	}
}
