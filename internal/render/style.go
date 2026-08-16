package render

import (
	"os"
	"strings"

	"github.com/krinos-dev/krinos/internal/model"
	"github.com/krinos-dev/krinos/internal/triage"
)

// Palette holds the 256-colour codes the renderer uses.
//
// The colours are chosen so that severity and verdict read at a glance
// without being shouty: the terminal is the only UI this product has, and a
// wall of red is exactly as unreadable as a wall of plain text.
const (
	colCritical = 203 // soft red
	colHigh     = 209 // orange
	colMedium   = 179 // amber
	colLow      = 109 // slate blue
	colInfo     = 245 // grey

	colAccent  = 67  // steel blue, used for structure only
	colSignal  = 173 // muted rust, used for the numbers that matter
	colOK      = 71  // green
	colDim     = 243 // secondary text
	colFaint   = 239 // tertiary text, rules and separators
	colInverse = 231 // near-white for emphasis on coloured ground
)

// Style renders text with optional ANSI colour and glyphs.
//
// Both switches are separate on purpose. Colour is about capability (is this
// a terminal?), glyphs are about encoding (will this console draw a box
// character or a mojibake blob?), and getting one wrong should not force the
// other off.
type Style struct {
	Color   bool
	Unicode bool
}

// DetectStyle decides how to render for the current process.
//
// It honours the NO_COLOR convention, disables colour when stdout is
// redirected — nobody wants escape codes in their CI artifact — and defaults
// glyphs off on Windows consoles, which still ship legacy code pages.
func DetectStyle(out *os.File, forceColor, forceNoColor, forceASCII bool) Style {
	s := Style{Color: true, Unicode: true}

	if info, err := out.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		s.Color = false
	}
	if _, set := os.LookupEnv("NO_COLOR"); set {
		s.Color = false
	}
	// CI systems render ANSI happily and their logs are more readable with
	// it, even though stdout is a pipe.
	if v := os.Getenv("CI"); v != "" && v != "false" && !forceNoColor {
		s.Color = true
	}
	if forceNoColor {
		s.Color = false
	}
	if forceColor {
		s.Color = true
	}
	if forceASCII {
		s.Unicode = false
	}
	return s
}

func (s Style) fg(code int, text string) string {
	if !s.Color {
		return text
	}
	return "\x1b[38;5;" + itoa(code) + "m" + text + "\x1b[0m"
}

func (s Style) bold(text string) string {
	if !s.Color {
		return text
	}
	return "\x1b[1m" + text + "\x1b[0m"
}

func (s Style) dim(text string) string   { return s.fg(colDim, text) }
func (s Style) faint(text string) string { return s.fg(colFaint, text) }

// chip renders a short label on a coloured ground, used for severity.
func (s Style) chip(code int, text string) string {
	if !s.Color {
		return text
	}
	return "\x1b[48;5;" + itoa(code) + "m\x1b[38;5;" + itoa(colInverse) + "m " + text + " \x1b[0m"
}

// glyph picks between a Unicode character and an ASCII stand-in.
func (s Style) glyph(unicode, ascii string) string {
	if s.Unicode {
		return unicode
	}
	return ascii
}

func (s Style) barFull() string  { return s.glyph("█", "#") }
func (s Style) barEmpty() string { return s.glyph("░", ".") }
func (s Style) rule() string     { return s.glyph("─", "-") }
func (s Style) arrow() string    { return s.glyph("→", "->") }

// severityColor maps a severity onto the palette.
func severityColor(sev model.Severity) int {
	switch sev {
	case model.SeverityCritical:
		return colCritical
	case model.SeverityHigh:
		return colHigh
	case model.SeverityMedium:
		return colMedium
	case model.SeverityLow:
		return colLow
	default:
		return colInfo
	}
}

// verdictColor maps a verdict onto the palette.
func verdictColor(v triage.Verdict) int {
	switch v {
	case triage.VerdictAct:
		return colSignal
	case triage.VerdictWatch:
		return colMedium
	default:
		return colDim
	}
}

// methodMark returns the leading mark for a piece of evidence. Proven
// evidence gets a check; heuristics get a dot, and never a check — the mark
// is a promise about how much the user should trust the line beside it.
func (s Style) methodMark(proven bool) string {
	if proven {
		return s.fg(colOK, s.glyph("✔", "+"))
	}
	return s.fg(colDim, s.glyph("·", "-"))
}

// itoa is a tiny non-allocating integer formatter for colour codes, which are
// always small and non-negative.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// comma formats an integer with thousands separators. The funnel numbers are
// the product's headline; "2,400" reads as a quantity, "2400" reads as an ID.
func comma(n int) string {
	s := itoaSigned(n)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	if len(s) <= 3 {
		if neg {
			return "-" + s
		}
		return s
	}

	var b strings.Builder
	lead := len(s) % 3
	if lead > 0 {
		b.WriteString(s[:lead])
	}
	for i := lead; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func itoaSigned(n int) string {
	if n < 0 {
		return "-" + itoa(-n)
	}
	return itoa(n)
}

// pad right-pads to width, ignoring ANSI sequences by taking the visible
// length from the caller. Callers pass plain text and colour it afterwards.
func pad(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

// padLeft left-pads to width for right-aligned numeric columns.
func padLeft(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return strings.Repeat(" ", width-len(s)) + s
}
