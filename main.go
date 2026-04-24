package main

import (
	"os"

	"github.com/yuuan/rails-session/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
