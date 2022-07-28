package webx

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/akkuman/iseeyou/logger"
	"github.com/akkuman/iseeyou/pkg/options"
	"github.com/akkuman/iseeyou/pkg/portscan"
	"github.com/akkuman/iseeyou/pkg/util"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/remeh/sizedwaitgroup"
	"github.com/spf13/cast"
	"go.uber.org/ratelimit"
)

const (
	SchemeHTTP  = "http"
	SchemeHTTPS = "https"
)

type HttpResponse struct {
	Body []byte
	Resp *http.Response
}

type Response struct {
	URL string
	Title string
	RespChain []HttpResponse
	Favicons []Favicon
	Fingerprints []string
	LogOutput string
}

// Favicon 存放favicon数据
type Favicon struct {
	MMH3 string
	MD5 string
	Data []byte
}

type WebX struct {
	opt             *options.Options

	Dialer  *fastdialer.Dialer
	client  *retryablehttp.Client
	limiter ratelimit.Limiter
}

func NewWebX(opt *options.Options) *WebX {
	var err error
	x := new(WebX)
	x.opt = opt
	// 增加限速器
	if opt.WebXRateLimit > 0 {
		x.limiter = ratelimit.New(opt.WebXRateLimit)
	} else {
		x.limiter = ratelimit.NewUnlimited()
	}
	// 创建客户端
	fastdialerOpts := fastdialer.DefaultOptions
	fastdialerOpts.EnableFallback = true
	fastdialerOpts.WithDialerHistory = true
	dialer, err := fastdialer.NewDialer(fastdialerOpts)
	if err != nil {
		logger.Fatalf("could not create resolver cache: %s", err)
	}
	x.Dialer = dialer
	var retryablehttpOptions = retryablehttp.DefaultOptionsSpraying
	retryablehttpOptions.Timeout = time.Duration(x.opt.WebXTimeout) * time.Second
	retryablehttpOptions.RetryMax = x.opt.WebXRetryMax
	// 禁用跳转，手动控制
	redirectFunc := func(redirectedRequest *http.Request, previousRequests []*http.Request) error {
		return http.ErrUseLastResponse
	}
	transport := &http.Transport{
		DialContext:         x.Dialer.Dial,
		MaxIdleConnsPerHost: -1,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
		DisableKeepAlives: true,
	}
	x.client = retryablehttp.NewWithHTTPClient(&http.Client{
		Transport:     transport,
		Timeout:       time.Duration(x.opt.WebXTimeout) * time.Second,
		CheckRedirect: redirectFunc,
	}, retryablehttpOptions)
	return x
}

func (x *WebX) Act(ctx context.Context, targets <-chan interface{}) <-chan interface{} {
	wg := sizedwaitgroup.New(x.opt.WebXThreadCount)
	resultChan := make(chan interface{}, 1000)
	go func() {
		defer close(resultChan)
		for target := range targets {
			switch v := target.(type) {
			case *portscan.IPPort:
				wg.Add()
				go func() {
					defer wg.Done()
					resp := x.Grab(ctx, v.IP.String(), v.Port)
					if resp != nil {
						// 填充log输出字段
						resp.LogOutput = buildLog(resp)
						resultChan <- resp
					}
				}()
			default:
				logger.Warnf("webx.Act 传入未知类型 %T", target)
				continue
			}
		}
		wg.Wait()
	}()
	return resultChan
}

func (x *WebX) buildRequest(ctx context.Context, targetURL string) (*retryablehttp.Request, error) {
	req, err := retryablehttp.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", options.DefaultUserAgent)
	req.Header.Add("Accept-Charset", "utf-8")
	return req, nil
}

// Grab 抓取页面内容，提取指纹
func (x *WebX) Grab(ctx context.Context, host string, port uint16) (*Response) {
	protocols := []string{SchemeHTTPS, SchemeHTTP}
	for _, protocol := range protocols {
		// 组装请求
		targetURL := fmt.Sprintf("%s://%s:%d", protocol, host, port)
		// 去除默认的端口
		switch {
		case protocol == SchemeHTTP && strings.HasSuffix(targetURL, ":80"):
			targetURL = strings.TrimSuffix(targetURL, ":80")
		case protocol == SchemeHTTPS && strings.HasSuffix(targetURL, ":443"):
			targetURL = strings.TrimSuffix(targetURL, ":443")
		}
		req, err := x.buildRequest(ctx, targetURL)
		if err != nil {
			logger.Warnf("构建web请求异常: %v", err)
			continue
		}
		// 获取首页内容
		resp, err := x.DoWebHTMLRequest(ctx, req)
		if err != nil {
			continue
		}
		// 填充url信息
		resp.URL = targetURL
		// 判断一些边界情况的协议切换
		if x.SwitchHTTPProtocol(ctx, resp) {
			continue
		}
		// 获取favicon
		resp.Favicons = x.getFavicon(ctx, resp)
		// 指纹识别
		fp1 := x.CheckNormalFingerprint(resp)
		// 获取特殊路径内容进行指纹识别
		fp2 := x.runSpecialFingerPrint(ctx, targetURL)
		// 合并指纹
		resp.Fingerprints = util.MergeStringList(fp1, fp2)
		// 请求成功则直接退出
		return resp
	}
	return nil
}

// SwitchHTTPProtocol 根据响应内容判断是否需要切换http请求
func (x *WebX) SwitchHTTPProtocol(ctx context.Context, resp *Response) bool {
	// 当对一个nginx的http开放端口发送https请求时，nginx会默认返回 400 The plain HTTP request was sent to HTTPS port
	if resp.Title == "400 The plain HTTP request was sent to HTTPS port" {
		for _, httpresp := range resp.RespChain {
			if httpresp.Resp.StatusCode == 400 {
				return true
			}
		}
	}
	return false
}

// CheckNormalFingerprint 检查常规请求是否命中指纹
func (x *WebX) CheckNormalFingerprint(resp *Response) ([]string) {
	fingerprintSet := util.NewStringSet()
	favicons := resp.Favicons
	for _, v := range resp.RespChain {
		for _, fingerprint := range FingerPrints {
			// 特殊指纹直接跳过
			if fingerprint.IsSpecial() {
				continue
			}
			if fingerprint.Match(v.Body, v.Resp, favicons) {
				fingerprintSet.Add(fingerprint.Name)
			}
		}
	}
	return fingerprintSet.GetList()
}

// runSpecialFingerPrint 执行特殊路径的指纹
func (x *WebX) runSpecialFingerPrint(ctx context.Context, baseURL string) ([]string) {
	fingerprintSet := util.NewStringSet()
	for _, fingerprint := range FingerPrints {
		// 跳过常规指纹
		if !fingerprint.IsSpecial() {
			continue
		}
		// url
		u, err := url.Parse(baseURL)
		if err != nil {
			logger.Warnf("解析url出错: %v", err)
			continue
		}
		uu, err := u.Parse(fingerprint.Path)
		if err != nil {
			logger.Warnf("解析url出错: %v", err)
			continue
		}
		targetURL := uu.String()
		// body
		var body []byte
		if fingerprint.HasRequestBody() {
			body, err = base64.StdEncoding.DecodeString(fingerprint.RequestData)
			if err != nil {
				logger.Warnf("该指纹中的请求体无法解析: %v", err)
				continue
			}
		}
		req, err := retryablehttp.NewRequestWithContext(ctx, fingerprint.RequestMethod, targetURL, body)
		if err != nil {
			logger.Warnf("构建特殊请求出错: %v", err)
			continue
		}
		// headers
		for k, v := range fingerprint.Headers {
			req.Header.Set(k, v)
		}
		// 发起请求
		respbody, httpresp, err := x.getResponse(ctx, req)
		if err != nil {
			continue
		}
		// 匹配指纹
		if fingerprint.Match(respbody, httpresp, nil) {
			fingerprintSet.Add(fingerprint.Name)
		}
	}
	return fingerprintSet.GetList()
}

// getBodyFromResp 获取响应并关闭body
func (x *WebX) getBodyFromResp(resp *http.Response) (body []byte, err error) {
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func (x *WebX) getFavicon(ctx context.Context, resp *Response) (favicons []Favicon) {
	faviconURLs := make(map[string]struct{})
	resps := resp.RespChain
	for i := range resps {
		// 对于服务器错误的情况，直接跳过
		if util.HttpStatusCode(resps[i].Resp.StatusCode).IsServerError() {
			continue
		}
		body := bytes.TrimSpace(resps[i].Body)
		// body为空，直接跳过
		if len(body) == 0 {
			continue
		}
		links := ExtractFaviconLink(body)
		// 浏览器在找不到favicon的情况下会自动访问该路径
		links = append(links, "/favicon.ico")
		for j := range links {
			iconURL, err := resps[i].Resp.Request.URL.Parse(links[j])
			if err != nil {
				logger.Warnf("拼接url出现问题: %v", err)
				continue
			}
			faviconURLs[iconURL.String()] = struct{}{}
		}
	}
	for faviconURL := range faviconURLs {
		req, err := x.buildRequest(ctx, faviconURL)
		if err != nil {
			continue
		}
		respbody, _, err := x.getResponse(ctx, req)
		if err != nil {
			continue
		}
		favicons = append(favicons, Favicon{
			MMH3: ShodanIconHash(respbody),
			MD5: MD5IconHash(respbody),
			Data: respbody,
		})
	}
	return
}

// getResponse 发送请求获取响应，注意：返回的 *http.Response 将不能再被读取body
// TODO: 关闭响应
func (x *WebX) getResponse(ctx context.Context, req *retryablehttp.Request) (respbody []byte, httpresp *http.Response, err error) {
	var gzipRetry bool
get_response:
	x.limiter.Take()
	httpresp, err = x.client.Do(req)
	if err != nil {
		return
	}
	// websockets don't have a readable body
	if httpresp.StatusCode == http.StatusSwitchingProtocols {
		return
	}
	respbody, err = x.getBodyFromResp(httpresp)
	if err != nil {
		// Edge case - some servers respond with gzip encoding header but uncompressed body, in this case the standard library configures the reader as gzip, triggering an error when read.
		// The bytes slice is not accessible because of abstraction, therefore we need to perform the request again tampering the Accept-Encoding header
		if !gzipRetry && strings.Contains(err.Error(), "gzip: invalid header") {
			gzipRetry = true
			req.Header.Set("Accept-Encoding", "identity")
			httpresp.Body.Close()
			goto get_response
		}
	}
	return
}

func (x *WebX) getRedirectURL(resp *http.Response, respbody []byte) (redirectURL string, is30X bool) {
	// 协议头跳转
	location := resp.Header.Get("Location")
	if location == "" {
		location = resp.Header.Get("location")
	}
	if location != "" {
		is30X = true

		u, _ := url.Parse(resp.Request.URL.String())
		uu, err := u.Parse(location)
		if err != nil {
			logger.Warnf("解析 headers location: %s 失败", location)
			return
		}
		redirectURL = uu.String()
		return
	}
	// 非协议头跳转
	redirectURL = ExtractRedirectURL(respbody)
	return
}

func (x *WebX) DoWebHTMLRequest(ctx context.Context, req *retryablehttp.Request) (*Response, error) {
	resp := new(Response)
	var chain []HttpResponse
	respbody, httpresp, err := x.getResponse(ctx, req)
	if err != nil {
		return nil, err
	}
	chain = append(chain, HttpResponse{
		Body: respbody,
		Resp: httpresp,
	})
	currentRedirectCount := 0
	for {
		// 计算跳转次数，达到最大值退出
		currentRedirectCount += 1
		if currentRedirectCount >= x.opt.WebXMaxRedirects {
			break
		}
		redirectURL, _ := x.getRedirectURL(httpresp, respbody)
		if redirectURL == "" {
			// 没有更多的跳转
			break
		}
		newURL, err := httpresp.Request.URL.Parse(redirectURL)
		if err != nil {
			logger.Warnf("拼接跳转url异常: %v", err)
			break
		}
		if newURL.String() == httpresp.Request.URL.String() {
			// 如果此次跳转和上一次跳转相同，则退出
			break
		}
		req, err = x.buildRequest(ctx, newURL.String())
		if err != nil {
			logger.Warnf("构建web请求异常: %v", err)
			break
		}
		previousHttpResp := httpresp
		respbody, httpresp, err = x.getResponse(ctx, req)
		if err != nil {
			logger.Warnf("%s 跳转后获取响应异常: %v", previousHttpResp.Request.URL.String(), err)
			break
		}
		chain = append(chain, HttpResponse{
			Body: respbody,
			Resp: httpresp,
		})
	}

	resp.RespChain = chain
	for i:=len(chain)-1 ; i >= 0; i-- {
		httpresp := chain[i].Resp
		respbody := chain[i].Body
		// 编码尝试，获取title
		respbody, err = httpx.DecodeData(respbody, httpresp.Header)
		if err != nil {
			return nil, err
		}
		resp.Title = ExtractTitle(respbody)
		// 如果已经获取到title，则退出
		if resp.Title != "" {
			break
		}
	}

	return resp, nil
}

// buildLog 构建日志
func buildLog(resp *Response) string {
	logText := ""
	logText += resp.URL
	// 组装状态码部分
	statusCodePart := ""
	statusCodePartColor := util.ColorGrenn
	var statusCodes []string
	for _, s := range resp.RespChain {
		statusCodes = append(statusCodes, cast.ToString(s.Resp.StatusCode))
		if s.Resp.StatusCode >= 300 && s.Resp.StatusCode < 400 {
			statusCodePartColor = util.ColorYellow
		} else if s.Resp.StatusCode >= 400 {
			statusCodePartColor = util.ColorRed
		}
	}
	if len(statusCodes) > 0 {
		statusCodePart = strings.Join(statusCodes, ",")
		statusCodePart = fmt.Sprintf("[%s]", statusCodePart)
		statusCodePart = statusCodePartColor(statusCodePart)
	}
	if statusCodePart != "" {
		logText += " " + statusCodePart
	}
	// 组装标题部分
	if resp.Title != "" {
		logText += " " + util.ColorBlue(resp.Title)
	}
	// 组装指纹部分
	fingerprintPart := ""
	if len(resp.Fingerprints) > 0 {
		fingerprintPart = strings.Join(resp.Fingerprints, ",")
		fingerprintPart = fmt.Sprintf("[%s]", fingerprintPart)
		fingerprintPart = util.ColorMagenta(fingerprintPart)
	}
	if fingerprintPart != "" {
		logText += " " + fingerprintPart
	}
	return logText
}