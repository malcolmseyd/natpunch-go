package antireplay

import (
	"testing"
)

func TestWindow(t *testing.T) {
	w := Window{}
	w.testCheck(t, 0, true)
	w.testCheck(t, 0, false)
	w.testCheck(t, 1, true)
	w.testCheck(t, 1, false)
	w.testCheck(t, 0, false)
	w.testCheck(t, 3, true)
	w.testCheck(t, 2, true)
	w.testCheck(t, 2, false)
	w.testCheck(t, 3, false)
	w.testCheck(t, 30, true)
	w.testCheck(t, 29, true)
	w.testCheck(t, 28, true)
	w.testCheck(t, 30, false)
	w.testCheck(t, 28, false)
	w.testCheck(t, WindowSize, true)
	w.testCheck(t, WindowSize, false)
	w.testCheck(t, WindowSize+1, true)

	w.Reset()
	w.testCheck(t, 0, true)
	w.testCheck(t, 1, true)
	w.testCheck(t, WindowSize, true)

	w.Reset()
	w.testCheck(t, WindowSize+1, true)
	w.testCheck(t, 0, false)
	w.testCheck(t, 1, true)
	w.testCheck(t, WindowSize+3, true)
	w.testCheck(t, 1, false)
	w.testCheck(t, 2, false)
	w.testCheck(t, WindowSize*3, true)
	w.testCheck(t, WindowSize*2-1, false)
	w.testCheck(t, WindowSize*2, true)
	w.testCheck(t, WindowSize*3, false)
}

func (w *Window) testCheck(t *testing.T, index uint64, expected bool) {
	result := w.Check(index)
	t.Log(index, "->", result)
	if result != expected {
		t.FailNow()
	}
}
