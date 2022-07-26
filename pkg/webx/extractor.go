package webx

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/akkuman/iseeyou/pkg/util"
	"github.com/projectdiscovery/stringsutil"
	"github.com/spf13/cast"
)

var (
	cutset        = "\n\t\v\f\r"
	reTitle       = regexp.MustCompile(`(?im)<\s*title.*>(.*?)<\s*/\s*title>`)
	reFaviconLink = regexp.MustCompile(`(?im)<\s*?link\s*?rel\s*?=\s*?"\s*?(shortcut icon|icon)\s*?"\s*?href\s*?=\s*?"\s*?(.+?)\s*?"\s*?>`)
	reRedirectURLInJS = []*regexp.Regexp {
		regexp.MustCompile(`(?im)\.location\.(open|replace)\(['"]?(?P<uri>.*?)['"]?\)`),
		regexp.MustCompile(`(?im)\.location.*?=\s*?['"](?P<uri>.*?)['"]`),
	}
	rePlainWord = regexp.MustCompile(`^[\p{L}\p{N}\s]+$`)
	titleGuestKeysInJSON = []string{"msg", "message"}
)

// ExtractRedirectURL from a response
func ExtractRedirectURL(data []byte) (redirectURI string) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	if err != nil {
		return
	}
	// 提取meta跳转
	doc.Find("meta[http-equiv]").Each(func(i int, s *goquery.Selection) {
		if goquery.NodeName(s) == "meta" {
			if v, ok := s.Attr("http-equiv"); ok {
				if strings.ToLower(v) != "refresh" {
					return
				}
				if content, exsit := s.Attr("content"); exsit {
					contentL := strings.Split(strings.TrimSpace(content), "=")
					if len(contentL) != 2 {
						return
					}
					redirectURI = strings.TrimSpace(contentL[1])
				}
			}
		}
	})
	if redirectURI != "" {
		return
	}
	// 提取js跳转
	bodytext := string(data)
	for _, r := range reRedirectURLInJS {
		subMatchMaps := util.ReSubMatchMap(r, bodytext, -1)
		// 提取js中最后一个跳转链接
		for _, m := range subMatchMaps {
			uri, ok := m["uri"]
			if !ok {
				continue
			}
			redirectURI = strings.TrimSpace(uri)
		}
	}
	return
}

// ExtractTitle from a response
func ExtractTitle(data []byte) (title string) {
	defer func() {
		// 移除非预期字符
		title = strings.TrimSpace(strings.Trim(title, cutset))
		title = stringsutil.ReplaceAny(title, "\n", "\r")
	}()
	data = bytes.TrimSpace(data)
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	if err != nil {
		// dom解析失败
		// 使用html title正则匹配
		for _, match := range reTitle.FindAllSubmatch(data, -1) {
			title = string(match[1])
			return
		}
	}
	doc.Find("title").Each(func(i int, s *goquery.Selection) {
		if goquery.NodeName(s) == "title" {
			title = s.Text()
		}
	})
	if title != "" {
		return
	}
	if rePlainWord.Match(data) {
		// 对于一些纯文本，可能一个网页上就一个SUCCESS，则把此类文本的第一行作为标题返回
		lines := bytes.Split(data, []byte("\n"))
		title = strings.TrimSpace(string(lines[0]))
	} else if bytes.HasPrefix(data, []byte("{")) && bytes.HasSuffix(data, []byte("}")) {
		// 对于一些首页返回json字典的情况，则将一些预置可能的键值作为标题返回
		dataMap := make(map[string]interface{})
		err = json.Unmarshal(data, &dataMap)
		if err != nil{
			return
		}
		for _, k := range titleGuestKeysInJSON {
			if v, ok := dataMap[k]; ok {
				title = cast.ToString(v)
			}
		}
	}

	return
}

// ExtractFaviconLink 从响应体中提取favicon链接
func ExtractFaviconLink(data []byte) (links []string) {
	fReMatch := func(s string) {
		for _, match := range reFaviconLink.FindAllStringSubmatch(string(s), -1) {
			links = append(links, match[2])
		}
	}
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	if err != nil {
		fReMatch(string(data))
		return
	}
	doc.Find("link[rel=shortcut icon],link[rel=icon]").Each(func(i int, s *goquery.Selection) {
		href, ok := s.Attr("href")
		if !ok {
			return
		}
		href = strings.TrimSpace(href)
		if href == "" {
			return
		}
		links = append(links, href)
	})
	if len(links) == 0 {
		fReMatch(string(data))
	}
	return
}