package util

import (
	"regexp"
	"testing"
)

// go test -v ./pkg/util/ -test.run TestReSubMatchMap
func TestReSubMatchMap(t *testing.T) {
	r := regexp.MustCompile(`<title>(?P<name>.*?)</title>`)
	s := "<title>你好</title>"
	subMatchMaps := ReSubMatchMap(r, s, -1)
	if len(subMatchMaps) != 1 {
		t.Fatal("len(subMatchMaps) != 1")
	}
	if subMatchMaps[0]["name"] != "你好" {
		t.Fatal(`subMatchMaps[0]["name"] != "你好"`)
	}
}