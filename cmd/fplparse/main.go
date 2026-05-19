package main

import (
	"fmt"
	"os"

	"github.com/faramesh/faramesh-core/internal/core/fpl"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: fplparse <file> [file...]")
		os.Exit(2)
	}

	for _, path := range os.Args[1:] {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			os.Exit(1)
		}
		if _, err := fpl.ParseDocument(string(data)); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			os.Exit(1)
		}
	}
}