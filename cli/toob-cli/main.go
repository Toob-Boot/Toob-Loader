package main

import (
	"os"

	"github.com/toob-boot/toob/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
