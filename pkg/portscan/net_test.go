package portscan

import (
	"testing"
)

func TestGetSrcParameters(t *testing.T) {
	srcip, netIface, err := GetSrcParameters("114.114.114.114")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("local ip is: %s\n, netIface is %s", srcip, netIface.Name)
}