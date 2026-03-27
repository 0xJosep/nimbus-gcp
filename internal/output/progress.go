package output

import (
	"fmt"
	"os"
	"sync"
)

const barWidth = 30

// ProgressBar renders an in-place progress bar to stderr.
type ProgressBar struct {
	mu      sync.Mutex
	total   int
	current int
	label   string
	isTerm  bool
}

// NewProgressBar creates a new progress bar with the given total count and label.
func NewProgressBar(total int, label string) *ProgressBar {
	isTerm := false
	if fi, err := os.Stderr.Stat(); err == nil {
		isTerm = (fi.Mode() & os.ModeCharDevice) != 0
	}
	pb := &ProgressBar{
		total:  total,
		label:  label,
		isTerm: isTerm,
	}
	pb.render()
	return pb
}

// Increment advances the progress bar by one step.
func (pb *ProgressBar) Increment() {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	if pb.current < pb.total {
		pb.current++
	}
	pb.render()
}

// Done completes the progress bar, filling it to 100% and printing a newline.
func (pb *ProgressBar) Done() {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	pb.current = pb.total
	pb.render()
	fmt.Fprintf(os.Stderr, "\n")
}

func (pb *ProgressBar) render() {
	pct := 0
	if pb.total > 0 {
		pct = pb.current * 100 / pb.total
	}

	filled := barWidth * pb.current / pb.total
	if pb.total == 0 {
		filled = 0
	}

	bar := make([]rune, barWidth)
	for i := range bar {
		if i < filled {
			bar[i] = '\u2588' // full block
		} else {
			bar[i] = '\u2591' // light shade
		}
	}

	line := fmt.Sprintf("[%s] %3d%% (%d/%d) %s",
		string(bar), pct, pb.current, pb.total, pb.label)

	if pb.isTerm {
		fmt.Fprintf(os.Stderr, "\r%s", line)
	} else {
		// Non-terminal: only print on completion or first call.
		if pb.current == pb.total || pb.current == 0 {
			fmt.Fprintf(os.Stderr, "%s\n", line)
		}
	}
}
