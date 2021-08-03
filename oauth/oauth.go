package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"github.com/fatih/color"
	"github.com/pkg/browser"
	"github.com/tidwall/pretty"
)

func AuthCodeFlow(tenantId string, clientId string, port string) {
	baseUrl, err := url.Parse(fmt.Sprintf("https://login.microsoftonline.com/%v/oauth2/v2.0/authorize", tenantId))
	if err != nil {
		fmt.Println("Malformed URL: ", err.Error())
		return
	}
	//http://localhost:8000/authorize?error=invalid_request&error_description=AADSTS900144%3a+The+request+body+must+contain+the+following+parameter%3a+%27response_type%27.%0d%0aTrace+ID%3a+6a78ae08-88ae-461f-bf11-0455b2bd4f01%0d%0aCorrelation+ID%3a+d5948273-65b1-490a-a9dc-29f4fb4b861d%0d%0aTimestamp%3a+2021-06-29+21%3a52%3a08Z&error_uri=https%3a%2f%2flogin.microsoftonline.com%2ferror%3fcode%3d900144#
	// Prepare Query Parameters
	params := url.Values{}
	params.Add("client_id", clientId)
	params.Add("redirect_uri", fmt.Sprintf("http://localhost:%v/authorize", port))
	params.Add("response_mode", "query")
	params.Add("response_type", "code")
	params.Add("scope", "user.read")
	baseUrl.RawQuery = params.Encode() // Escape Query Parameters
	fmt.Println(baseUrl.String())
	err = browser.OpenURL(baseUrl.String())
	if err != nil {
		fmt.Println(err)
	}
}
func ImplicitGrantFlow(clientId string, option public.Option) string {
	publicClientApp, err := public.New(clientId, option)
	if err != nil {
		log.Fatalf("creating public client: %v", err)
	}
	var userAccount public.Account
	var token string
	accounts := publicClientApp.Accounts()
	if len(accounts) > 0 {
		// Assuming the user wanted the first account
		userAccount = accounts[0]
		// found a cached account, now see if an applicable token has been cached
		result, err := publicClientApp.AcquireTokenSilent(context.Background(), []string{"User.Read"}, public.WithSilentAccount(userAccount))
		if err != nil {
			log.Fatalf("acquire token silent: %v", err)
		}
		b, err := json.MarshalIndent(result, "", "")
		if err != nil {
			log.Fatalf("AuthResult: %v", err)
		}
		fmt.Println(string(pretty.Color(pretty.Pretty(b), pretty.TerminalStyle)))
		token= result.AccessToken
	}
	return token

}
func DeviceCodeFlow(tenantId string, clientId string, secret string, option public.Option) {
	publicClientApp, err := public.New(clientId, option)
	if err != nil {
		log.Fatalf("creating new client: %v", err)
	}
	r, err := publicClientApp.AcquireTokenByDeviceCode(context.Background(), []string{"User.Read"})
	if err != nil {
		log.Fatalf("calling acquire token by device code: %v", err)
	}
	result := r.Result
	fmt.Printf("Visit: %v and Enter: %v\n", result.VerificationURL, result.UserCode)
	client := http.DefaultClient
	deviceResult, err := WaitForDeviceAuthorization(tenantId, secret, client, &result)
	if err != nil {
		log.Fatalf("Device authorization result: %v", err)
	}
	b, err := ioutil.ReadAll(deviceResult.Body)
	if err != nil {
		log.Fatalf("Device code result to json: %v", err)
	}
	fmt.Println(string(pretty.Color(pretty.Pretty(b), pretty.TerminalStyle)))
}
func Interactive(clientId string, option public.Option) string {
	publicClientApp, err := public.New(clientId, option)
	if err != nil {
		log.Fatalf("creating new client: %v", err)
	}
	opt:=public.WithRedirectURI("http://localhost:8000/token")
	r, err := publicClientApp.AcquireTokenInteractive(context.Background(), []string{"User.Read"},opt)
	if err != nil {
		log.Fatalf("AcquireTokenInteractive: %v", err)
	}
	b, err := json.MarshalIndent(r, "", "")
	if err != nil {
		log.Fatalf("AuthResult: %v", err)
	}
	fmt.Println(string(pretty.Color(pretty.Pretty(b), pretty.TerminalStyle)))
	return r.AccessToken
}
func UsernamePassword(clientId string, username string, password string, option public.Option) string {
	publicClientApp, err := public.New(clientId, option)
	if err != nil {
		log.Fatalf("creating new client: %v", err)
	}
	r, err := publicClientApp.AcquireTokenByUsernamePassword(context.Background(), []string{"User.Read"}, username, password)
	if err != nil {
		log.Fatalf("AcquireTokenByUsernamePassword: %v", err)
	}
	b, err := json.MarshalIndent(r, "", "")
	if err != nil {
		log.Fatalf("AuthResult: %v", err)
	}
	fmt.Println(string(pretty.Color(pretty.Pretty(b), pretty.TerminalStyle)))
	return r.AccessToken
}

// WaitForDeviceAuthorization polls the token URL waiting for the user to
// authorize the app. Upon authorization, it returns the new token. If
// authorization fails then an error is returned. If that failure was due to a
// user explicitly denying access, the error is ErrAccessDenied.
func WaitForDeviceAuthorization(tenantId string, secret string, client *http.Client, config *public.DeviceCodeResult) (*http.Response, error) {
	grantType := "urn:ietf:params:oauth:grant-type:device_code"
	yellow := color.New(color.FgYellow, color.Bold)
	blue := color.New(color.FgBlue, color.Bold)
	for {

		resp, err := client.PostForm(fmt.Sprintf("https://login.microsoftonline.com/%v/oauth2/v2.0/token", tenantId),
			url.Values{
				"client_secret": {secret},
				"client_id":     {config.ClientID},
				"device_code":   {config.DeviceCode},
				"grant_type":    {grantType}})
		if err != nil {
			return nil, err
		}
		// 400 status code (StatusBadRequest) is our sign that the user
		// hasn't completed their device login yet, sleep and then continue.
		if resp.StatusCode == http.StatusBadRequest {

			// Sleep for the retry interval and print a dot for each second.
			for i := 0; i < config.Interval; i++ {
				if i == 0 {
					blue.Printf(".")
				} else {
					yellow.Printf(".")
				}
				time.Sleep(time.Second)
			}

			continue
		}
		return resp, nil
	}
}
