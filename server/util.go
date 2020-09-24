package main

import (
	"fmt"
	"os"
)

func Eprintln(a ...interface{}) {
	fmt.Fprintln(os.Stderr, a...)
}

func Eprint(a ...interface{}) {
	fmt.Fprint(os.Stderr, a...)
}

func Eprintf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format, a...)
}

func Fatalln(a ...interface{}) {
	Eprintln(a...)
	os.Exit(1)
}

func Fatal(a ...interface{}) {
	Eprint(a...)
	os.Exit(1)
}

func Fatalf(format string, a ...interface{}) {
	Eprintf(format, a...)
	os.Exit(1)
}
