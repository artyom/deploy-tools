// Package isterm provides a function to test whether standard output is
// terminal or not.
package isterm

import "os"

// IsTerminal returns true if stdout is attached to terminal (it's a device file).
func IsTerminal() bool {
	st, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeDevice != 0
}
