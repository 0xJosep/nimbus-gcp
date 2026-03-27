package output

import (
	"fmt"
	"os"
	"sync"
	"time"
)

var spinnerFrames = []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

// Spinner displays an animated progress spinner on stderr.
type Spinner struct {
	mu      sync.Mutex
	message string
	active  bool
	stop    chan struct{}
	done    chan struct{}
	isTerm  bool
}

// NewSpinner creates a new Spinner. It detects whether stderr is a terminal;
// if not, animation is disabled and messages are printed as plain lines.
func NewSpinner() *Spinner {
	isTerm := false
	if fi, err := os.Stderr.Stat(); err == nil {
		isTerm = (fi.Mode() & os.ModeCharDevice) != 0
	}
	return &Spinner{
		isTerm: isTerm,
	}
}

// Start begins the spinner with the given message.
func (s *Spinner) Start(message string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.active {
		return
	}

	s.message = message
	s.active = true
	s.stop = make(chan struct{})
	s.done = make(chan struct{})

	if !s.isTerm {
		fmt.Fprintf(os.Stderr, "%s\n", message)
		return
	}

	go s.loop()
}

// Update changes the spinner message while it is running.
func (s *Spinner) Update(message string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.message = message

	if !s.isTerm && s.active {
		fmt.Fprintf(os.Stderr, "%s\n", message)
	}
}

// Stop halts the spinner and prints a final message on the cleared line.
func (s *Spinner) Stop(finalMessage string) {
	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return
	}
	s.active = false
	s.mu.Unlock()

	if s.isTerm {
		close(s.stop)
		<-s.done
		// Clear the line and print the final message.
		fmt.Fprintf(os.Stderr, "\r\033[K%s\n", finalMessage)
	} else {
		fmt.Fprintf(os.Stderr, "%s\n", finalMessage)
	}
}

func (s *Spinner) loop() {
	defer close(s.done)

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	frame := 0
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.mu.Lock()
			msg := s.message
			s.mu.Unlock()

			ch := spinnerFrames[frame%len(spinnerFrames)]
			fmt.Fprintf(os.Stderr, "\r\033[K%c %s", ch, msg)
			frame++
		}
	}
}
