package output

import "os"

// ColorEnabled controls whether color output is active.
var ColorEnabled = true

// DisableColor turns off all color output by clearing the ANSI escape variables.
func DisableColor() {
	ColorEnabled = false
	Reset = ""
	Red = ""
	Green = ""
	Yellow = ""
	Blue = ""
	Cyan = ""
	Bold = ""
	Dim = ""
}

// DetectColor checks if stdout is a terminal and auto-disables color if not.
// This allows piped output (e.g. nimbus modules | grep storage) to be clean.
func DetectColor() {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return
	}
	if (fi.Mode() & os.ModeCharDevice) == 0 {
		DisableColor()
	}
}
