package targets

import (
	"context"
	"testing"

	"github.com/akkuman/iseeyou/pkg/options"
)

func TestTargetBuilderAct(t *testing.T) {
	opt := &options.Options{
		ScanPorts: "top100",
	}
	opt.Init()
	p := NewTargetBuilder(opt)
	inCh := make(chan interface{}, 10)
	inCh <- "127.0.0.1/24"
	close(inCh)
	result := p.Act(context.Background(), inCh)
	for v := range result {
		t.Logf("%#v", v)
	}
}