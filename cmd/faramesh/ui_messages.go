package main

import (
	"fmt"

	"github.com/fatih/color"
)

var (
	labelError   = color.New(color.Bold, color.FgRed)
	labelWarn    = color.New(color.Bold, color.FgYellow)
	labelNote    = color.New(color.Bold, color.FgCyan)
	labelTip     = color.New(color.Bold, color.FgMagenta)
	labelNext    = color.New(color.Bold, color.FgBlue)
	labelSuccess = color.New(color.Bold, color.FgGreen)
	labelReady   = color.New(color.Bold, color.FgGreen)
)

func printErrorLine(msg string) {
	printLabeledLine(labelError, "ERROR", msg)
}

func printWarningLine(msg string) {
	printLabeledLine(labelWarn, "WARNING", msg)
}

func printNoteLine(msg string) {
	printLabeledLine(labelNote, "NOTE", msg)
}

func printTipLine(msg string) {
	printLabeledLine(labelTip, "TIP", msg)
}

func printNextStepLine(msg string) {
	printLabeledLine(labelNext, "NEXT STEP", msg)
}

func printSuccessLine(msg string) {
	printLabeledLine(labelSuccess, "SUCCESS", msg)
}

func printReadyLine(msg string) {
	printLabeledLine(labelReady, "READY", msg)
}

func printLabeledLine(style *color.Color, label string, msg string) {
	style.Printf("%s", label)
	fmt.Printf(": %s\n", msg)
}
