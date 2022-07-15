package portscan

import "time"

const (
	ExternalTargetForTune = "8.8.8.8"
	// SYNPacketLen syn包长
	SYNPacketLen = 60
	DefaultWarmUpTime = 5 * time.Second
)