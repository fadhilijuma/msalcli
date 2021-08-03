package main

import (
	"context"
	_ "embed"
	"os"
	"os/signal"
	"syscall"

	"github.com/fadhilijuma/msalcli/cmd/oauthcli"
	"github.com/fadhilijuma/msalcli/logger"
)

var log = logger.New("OauthCli")

func main() {
	//Initialise cli.
	cli := oauthcli.New(log)
	if err := cli.ParseAndRun(context.Background(), os.Args[1:]); err != nil {
		log.Fatal(err)
	}
	// Make a channel to listen for an interrupt or terminate signal from the OS.
	// Use a buffered channel because the signal package requires it.
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	<-shutdown

}
