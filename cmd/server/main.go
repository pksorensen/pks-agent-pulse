package main

import (
	"os"

	"github.com/pksorensen/pks-agent-pulse/internal/cli"
)

func main() {
	args := append([]string{"serve"}, os.Args[1:]...)
	os.Exit(cli.Run(args, "server"))
}
