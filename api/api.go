package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"github.com/fadhilijuma/msalcli/config"
	"github.com/tidwall/pretty"
	"go.uber.org/zap"
)

type Config struct {
	ClientId string
	TenantId string
	Port string
	Logger *zap.SugaredLogger
}

func Run(log *zap.SugaredLogger) {
	cfg:=config.New()

	cg:= Config{
		ClientId: cfg.ClientId,
		TenantId: cfg.TenantId,
		Port: cfg.Port,
		Logger:   log,
	}

	mux := http.NewServeMux()
	mux.Handle("/authorize", http.HandlerFunc(cg.authorise))
	mux.Handle("/token", http.HandlerFunc(cg.token))
	api := http.Server{
		Addr:         fmt.Sprintf("localhost:%v", cfg.Port),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		ErrorLog:     zap.NewStdLog(log.Desugar()),
	}

	// Make a channel to listen for errors coming from the listener. Use a
	// buffered channel so the goroutine can exit if we don't collect this error.
	serverErrors := make(chan error, 1)

	// Start the service listening for requests.
	go func() {
		log.Infof("main.Run : API listening on %s", api.Addr)
		serverErrors <- api.ListenAndServe()
	}()

	// Make a channel to listen for an interrupt or terminate signal from the OS.
	// Use a buffered channel because the signal package requires it.
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// =========================================================================
	// Shutdown

	// Blocking main and waiting for shutdown.
	select {
	case err := <-serverErrors:
		log.Fatalf("error: listening and serving: %s", err)

	case <-shutdown:
		log.Info("main : Start shutdown")

		// Give outstanding requests a deadline for completion.
		const timeout = 5 * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Asking listener to shutdown and load shed.
		err := api.Shutdown(ctx)
		if err != nil {
			log.Errorf("main : Graceful shutdown did not complete in %v : %v", timeout, err)
			err = api.Close()
		}

		if err != nil {
			log.Fatalf("main : could not stop server gracefully : %v", err)
		}
	}

}

func (cfg *Config) authorise(w http.ResponseWriter, r *http.Request) {
	log := cfg.Logger
	code := r.URL.Query().Get("code")
	publicClientApp, err := public.New(cfg.ClientId, public.WithAuthority(fmt.Sprintf("https://login.microsoftonline.com/%v", cfg.TenantId)))
	if err != nil {
		log.Errorf("authorise code: %v\n", err)
	}
	p, err := publicClientApp.AcquireTokenByAuthCode(context.Background(), code, fmt.Sprintf("http://localhost:%v/authorize", cfg.Port), []string{"user.read"})
	if err != nil {
		log.Errorf("authorise token: %v", err)
	}
	b, err := json.MarshalIndent(p, "", "")
	if err != nil {
		log.Errorf("encoding authResult: %v", err)
	}
	fmt.Println(string(pretty.Color(pretty.Pretty(b), pretty.TerminalStyle)))
}
func (cfg *Config) token(w http.ResponseWriter, r *http.Request) {
	log := cfg.Logger
	req, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorf("token: %v\n", err)
	}
	fmt.Println(string(pretty.Color(pretty.Pretty(req), pretty.TerminalStyle)))
}
