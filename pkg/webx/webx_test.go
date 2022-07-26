package webx

import (
	"context"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/akkuman/iseeyou/pkg/options"
	"github.com/akkuman/iseeyou/pkg/portscan"
)

// go test -v ./pkg/webx/ -test.run TestWebXAct
func TestWebXAct(t *testing.T) {
	opt := options.Options{
		WebXThreadCount: 50,
	}
	x := NewWebX(&opt)
	inCh := make(chan interface{}, 10)
	inCh <- &portscan.IPPort{
		IP: net.ParseIP("121.4.36.116"),
		Port: 1433,
	}
	close(inCh)
	outCh := x.Act(context.Background(), inCh)
	for v := range outCh {
		vv := v.(Response)
		t.Logf("%#v", vv)
	}
}

// go test -v ./pkg/webx/ -test.run TestGetInfo
func TestGetInfo(t *testing.T) {
	doc, err := goquery.NewDocument("http://118.213.59.20/")
	if err != nil {
		t.Fatal(err)
	}
	doc.Find("meta[http-equiv]").Each(func(i int, s *goquery.Selection) {
		if goquery.NodeName(s) == "meta" {
			if v, ok := s.Attr("http-equiv"); ok {
				if strings.ToLower(v) != "refresh" {
					return
				}
				if content, exsit := s.Attr("content"); exsit {
					contentL := strings.Split(strings.TrimSpace(content), "=")
					if len(contentL) != 2 {
						t.Error("处理 meta refresh 异常")
						return
					}
					u, _ := url.Parse("http://127.0.0.1")
					uu, _ := u.Parse(contentL[1])
					t.Log(uu.String())
				}
			}
		}
	})
}