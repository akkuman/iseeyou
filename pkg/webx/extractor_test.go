package webx

import "testing"

// go test -v ./pkg/webx/ -test.run TestExtractRedirectURL
func TestExtractRedirectURL(t *testing.T) {
	var flagtests = []struct {
		in  string
		out string
	}{
		{`<html><meta charset='utf-8'/><style>body{background:white}</style><script>self.location='/index.php?m=user&f=login&referer=lw==';</script>`, "/index.php?m=user&f=login&referer=lw=="},
		{`<script> window.location.replace("login.jsp?up=1");</script>`, `login.jsp?up=1`},
		{`window.location.href = "../cgi-bin/login.cgi?requestname=2&cmd=0";`, `../cgi-bin/login.cgi?requestname=2&cmd=0`},
	}
	for _, tt := range flagtests {
		t.Run(tt.in, func(t *testing.T) {
            s := ExtractRedirectURL([]byte(tt.in))
            if s != tt.out {
                t.Errorf("got %q, want %q", s, tt.out)
            }
        })
	}
}
