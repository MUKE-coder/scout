package cli

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/term"

	"github.com/MUKE-coder/scout/engine"
)

// optimisticPhases are reassuring, roughly-ordered messages shown while a scan
// runs. The index advances with real progress, so the words track the work.
var optimisticPhases = []string{
	"Warming up the scanner…",
	"Crawling the application…",
	"Mapping the attack surface…",
	"Checking security headers…",
	"Inspecting TLS & certificates…",
	"Looking for exposed files…",
	"Probing endpoints & auth…",
	"Reviewing DNS & email records…",
	"Scanning code & dependencies…",
	"Scoring and grading…",
	"Almost there…",
}

var spinnerFrames = []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

// progressReporter renders a live, single-line scan status to a terminal while
// checks run. It subscribes to the engine's event bus. On a non-terminal
// writer (pipes, CI) it does nothing, so logs stay clean.
type progressReporter struct {
	w        io.Writer
	color    bool
	unsub    func()
	ch       <-chan engine.Event
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
	mu       sync.Mutex
	target   string
	total    int
	done     int
	started  bool
}

// startProgress wires a reporter to the bus and starts rendering. It returns a
// no-op reporter when w is not a terminal, so callers need not branch.
func startProgress(bus *engine.Bus, w io.Writer, color bool) *progressReporter {
	p := &progressReporter{w: w, color: color, stopCh: make(chan struct{})}
	f, ok := w.(*os.File)
	if bus == nil || !ok || !term.IsTerminal(int(f.Fd())) { // #nosec G115 -- fd fits in int
		return p // inert
	}
	p.ch, p.unsub = bus.Subscribe(256)
	p.wg.Add(1)
	go p.loop()
	return p
}

// setTarget names the target currently being scanned, shown in the status line.
func (p *progressReporter) setTarget(name string) {
	p.mu.Lock()
	p.target = name
	p.mu.Unlock()
}

func (p *progressReporter) loop() {
	defer p.wg.Done()
	ticker := time.NewTicker(110 * time.Millisecond)
	defer ticker.Stop()
	frame := 0
	for {
		select {
		case <-p.stopCh:
			return
		case ev, ok := <-p.ch:
			if !ok {
				return
			}
			p.mu.Lock()
			switch ev.Type {
			case engine.EventScanStarted:
				p.total, p.done, p.started = ev.Total, 0, true
			case engine.EventCheckFinished:
				if ev.Done > p.done {
					p.done = ev.Done
				}
				if ev.Total > p.total {
					p.total = ev.Total
				}
			}
			p.mu.Unlock()
		case <-ticker.C:
			p.render(spinnerFrames[frame%len(spinnerFrames)])
			frame++
		}
	}
}

func (p *progressReporter) render(spin rune) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started {
		return
	}
	phase := optimisticPhases[0]
	if p.total > 0 {
		idx := p.done * (len(optimisticPhases) - 1) / p.total
		if idx >= len(optimisticPhases) {
			idx = len(optimisticPhases) - 1
		}
		phase = optimisticPhases[idx]
	}
	count := ""
	if p.total > 0 {
		count = fmt.Sprintf(" [%d/%d]", p.done, p.total)
	}
	tgt := ""
	if p.target != "" {
		tgt = " · " + p.target
	}
	line := fmt.Sprintf("%c %s%s%s", spin, phase, count, tgt)
	if p.color {
		// dim the metadata, accent the spinner
		line = fmt.Sprintf("\x1b[36m%c\x1b[0m %s\x1b[2m%s%s\x1b[0m", spin, phase, count, tgt)
	}
	// pad to clear any longer previous line
	fmt.Fprintf(p.w, "\r%-78s\r%s", "", line)
}

// stop ends rendering and clears the status line. It is safe to call more than
// once (the scan path calls it explicitly and again via defer).
func (p *progressReporter) stop() {
	if p.unsub == nil {
		return
	}
	p.stopOnce.Do(func() {
		close(p.stopCh)
		p.unsub()
		p.wg.Wait()
		fmt.Fprintf(p.w, "\r%-78s\r", "") // clear the line
	})
}

// progressWriter is where the live status line goes: stderr, so stdout keeps
// only the report (or JSON). Overridable in tests.
var progressWriter io.Writer = os.Stderr
