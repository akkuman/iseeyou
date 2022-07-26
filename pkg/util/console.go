package util

import "github.com/fatih/color"

var (
	ColorYellow  = color.New(color.FgYellow).SprintFunc()
	ColorRed     = color.New(color.FgRed).SprintFunc()
	ColorGrenn   = color.New(color.FgGreen).SprintFunc()
	ColorBlue    = color.New(color.FgBlue).SprintFunc()
	ColorMagenta = color.New(color.FgMagenta).SprintFunc()
)
