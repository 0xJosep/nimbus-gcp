package output

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Colors for terminal output.
const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Cyan   = "\033[36m"
	Bold   = "\033[1m"
	Dim    = "\033[2m"
)

// Info prints an informational message.
func Info(format string, args ...any) {
	fmt.Printf(Cyan+"[*] "+Reset+format+"\n", args...)
}

// Success prints a success message.
func Success(format string, args ...any) {
	fmt.Printf(Green+"[+] "+Reset+format+"\n", args...)
}

// Warn prints a warning message.
func Warn(format string, args ...any) {
	fmt.Printf(Yellow+"[!] "+Reset+format+"\n", args...)
}

// Error prints an error message.
func Error(format string, args ...any) {
	fmt.Printf(Red+"[-] "+Reset+format+"\n", args...)
}

// Table prints data as a formatted table.
func Table(headers []string, rows [][]string) {
	if len(rows) == 0 {
		fmt.Println("  No results.")
		return
	}

	// Calculate column widths.
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Print header.
	fmt.Println()
	for i, h := range headers {
		fmt.Printf("  "+Bold+"%-*s"+Reset, widths[i]+2, h)
	}
	fmt.Println()
	for i := range headers {
		fmt.Printf("  %-*s", widths[i]+2, strings.Repeat("-", widths[i]))
	}
	fmt.Println()

	// Print rows.
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) {
				fmt.Printf("  %-*s", widths[i]+2, cell)
			}
		}
		fmt.Println()
	}
	fmt.Println()
}

// JSON prints data as formatted JSON.
func JSON(v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		Error("json marshal: %v", err)
		return
	}
	fmt.Println(string(data))
}
