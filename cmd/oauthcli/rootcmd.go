package oauthcli

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"github.com/fadhilijuma/msalcli/api"
	"github.com/fadhilijuma/msalcli/config"
	"github.com/fadhilijuma/msalcli/oauth"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"
	"github.com/tidwall/pretty"
	"go.uber.org/zap"
)

var (
	rootFlagSet = flag.NewFlagSet("msalcli", flag.ExitOnError)
	username    = rootFlagSet.String("username", "", "email address")
	password   = rootFlagSet.String("password", "", "password")
	cfg         = config.New()
)

func New(log *zap.SugaredLogger) *ffcli.Command {
	authCode := &ffcli.Command{
		Name:       "code",
		ShortUsage: "msalcli code",
		ShortHelp:  "Runs the Authorization Code Oauth2 Flow example.",
		FlagSet: flag.NewFlagSet("ocli code", flag.ExitOnError),
		Exec: func(_ context.Context, args []string) error {
			oauth.AuthCodeFlow(cfg.TenantId, cfg.ClientId, cfg.Port)
			return nil
		},
	}
	deviceCode := &ffcli.Command{
		Name:       "d",
		ShortUsage: "msalcli d",
		ShortHelp:  "Runs the Device Code Oauth2 Flow example.",
		FlagSet: flag.NewFlagSet("ocli d", flag.ExitOnError),
		Exec: func(_ context.Context, args []string) error {
			option := public.WithAuthority(fmt.Sprintf("https://login.microsoftonline.com/%v", cfg.TenantId))
			oauth.DeviceCodeFlow(cfg.TenantId, cfg.ClientId, cfg.Secret, option)
			return nil
		},
	}
	interactive := &ffcli.Command{
		Name:       "i",
		ShortUsage: "msalcli i",
		ShortHelp:  "Runs the Interactive Oauth2 Flow example.",
		FlagSet: flag.NewFlagSet("ocli i", flag.ExitOnError),
		Exec: func(_ context.Context, args []string) error {
			option := public.WithAuthority(fmt.Sprintf("https://login.microsoftonline.com/%v", cfg.TenantId))
			token := oauth.Interactive(cfg.ClientId, option)
			b, err := callGraphApi(token)
			if err != nil {
				log.Fatalf("callGraphApi: %v", err)
			}
			fmt.Println(string(pretty.Color(pretty.Pretty(b), pretty.TerminalStyle)))
			return nil
		},
	}
	implicit := &ffcli.Command{
		Name:       "g",
		ShortUsage: "msalcli g",
		ShortHelp:  "Runs the Implicit Grant Oauth2 Flow example.",
		FlagSet: flag.NewFlagSet("ocli g", flag.ExitOnError),
		Exec: func(_ context.Context, args []string) error {
			option := public.WithAuthority(fmt.Sprintf("https://login.microsoftonline.com/%v", cfg.TenantId))
			token := oauth.ImplicitGrantFlow(cfg.ClientId, option)
			b, err := callGraphApi(token)
			if err != nil {
				log.Fatalf("callGraphApi: %v", err)
			}
			fmt.Println(string(pretty.Color(pretty.Pretty(b), pretty.TerminalStyle)))
			return nil
		},
	}
	usernamePassword := &ffcli.Command{
		Name:       "u",
		ShortUsage: "msalcli up [flags]",
		ShortHelp:  "Runs the Username and Password Oauth2 Flow.",
		FlagSet:    rootFlagSet,
		Exec: func(_ context.Context, args []string) error {
			option := public.WithAuthority(fmt.Sprintf("https://login.microsoftonline.com/%v", cfg.TenantId))
			token := oauth.UsernamePassword(cfg.ClientId, *username, *password, option)
			b, err := callGraphApi(token)
			if err != nil {
				log.Fatalf("callGraphApi: %v", err)
			}
			fmt.Println(string(pretty.Color(pretty.Pretty(b), pretty.TerminalStyle)))
			return nil
		},
	}
	apiRoot := &ffcli.Command{
		Name:       "api",
		ShortUsage: "msalcli api",
		ShortHelp:  "Runs the oauth2 api response urls.",
		FlagSet:    rootFlagSet,
		Exec: func(_ context.Context, args []string) error {
			api.Run(log)
			return nil
		},
	}
	root := &ffcli.Command{
		Name:        "msalcli",
		ShortUsage:  "msalcli <subcommand>",
		FlagSet:     rootFlagSet,
		Subcommands: []*ffcli.Command{authCode, implicit, deviceCode, interactive, usernamePassword,apiRoot},
		Exec: func(context.Context, []string) error {
			return nil
		},
	}
	return root
}
func callGraphApi(bearer string) ([]byte, error) {
	r, err := http.NewRequest(http.MethodGet, "https://graph.microsoft.com/v1.0/me/", nil)
	if err != nil {
		return nil, errors.Wrap(err, "creating new request")
	}
	r.Header.Add("Authorization", fmt.Sprintf("Bearer %v", bearer))
	client := http.Client{}
	resp, err := client.Do(r)
	if err != nil {
		return nil, errors.Wrap(err, "requesting MSGraph")
	}
	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, errors.Wrap(err, "reading response from MSGraph")
	}
	return body, nil

}
