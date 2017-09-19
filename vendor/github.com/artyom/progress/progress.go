// Package progress provides an io.Writer that prints number of written bytes to
// stdout in a pretty way.
//
// Use io.MultiWriter to chain it together with you destination writer like
// this:
//
//	f, err := os.Open(...)
//	...
//	fi, err := f.Stat()
//	...
// 	n, err := io.Copy(io.MultiWriter(dst, progress.New(fi.Size())), src)
package progress

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// New initializes new Writer printing progress to os.Stdout. If total is 0 or
// negative, only number of written bytes is printed.
func New(total int64) *Writer {
	return &Writer{
		Total:  total,
		Output: os.Stdout,
	}
}

// Writer on each Write call prints a progress info to os.Stdout. Progress
// format is "sum/total" ending with carriage return, so if os.Stdout is
// attached to a terminal output would update the same line over and over.
type Writer struct {
	Total  int64     // total number of bytes to be written, if known
	Output io.Writer // progress is written here, os.Stout by default

	totalStr string
	sum      int
	once     sync.Once
}

// Write always returns len(p), nil,
func (w *Writer) Write(p []byte) (int, error) {
	w.once.Do(func() {
		if w.Output == nil {
			w.Output = os.Stdout
		}
		if w.Total > 0 {
			w.totalStr = fmt.Sprintf("%8v", byteSize(w.Total))
		}
	})
	plen := len(p)
	w.sum += plen
	if w.Total > 0 {
		fmt.Fprintf(w.Output, "%8v/%s\r", byteSize(w.sum), w.totalStr)
	} else {
		fmt.Fprintf(w.Output, "%8v\r", byteSize(w.sum))
	}
	return plen, nil
}

type byteSize float64

const (
	_           = iota // ignore first value by assigning to blank identifier
	kb byteSize = 1 << (10 * iota)
	mb
	gb
	tb
	pb
	eb
	zb
	yb
)

func (b byteSize) String() string {
	switch {
	case b >= yb:
		return fmt.Sprintf("%.2fYB", b/yb)
	case b >= zb:
		return fmt.Sprintf("%.2fZB", b/zb)
	case b >= eb:
		return fmt.Sprintf("%.2fEB", b/eb)
	case b >= pb:
		return fmt.Sprintf("%.2fPB", b/pb)
	case b >= tb:
		return fmt.Sprintf("%.2fTB", b/tb)
	case b >= gb:
		return fmt.Sprintf("%.2fGB", b/gb)
	case b >= mb:
		return fmt.Sprintf("%.2fMB", b/mb)
	case b >= kb:
		return fmt.Sprintf("%.2fKB", b/kb)
	}
	return fmt.Sprintf("%.2fB", b)
}
