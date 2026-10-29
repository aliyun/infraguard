package cmd

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("INFRAGUARD_SERVER_WORKER_TEST") == "1" && len(os.Args) > 2 && os.Args[1] == "server" && os.Args[2] == "__run" {
		if err := Execute(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	m.Run()
}
