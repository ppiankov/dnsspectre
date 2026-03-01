package main

import (
	"fmt"
	"os"

	"github.com/ppiankov/dnsspectre/internal/commands"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	vi := commands.VersionInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}
	if err := commands.Execute(vi); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}
