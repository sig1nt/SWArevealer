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

const CLIENT_ID = "okta.2b1959c8-bcc0-56eb-a589-cfcfb7422f26"

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

func getOauthToken(client *http.Client, baseUrl *url.URL) (*oauth2.Token, error) {

	authUrl, err := baseUrl.Parse("/oauth2/v1/authorize")
	if err != nil {
		return nil, err
	}

	tokenUrl, err := baseUrl.Parse("/oauth2/v1/token")
	if err != nil {
		return nil, err
	}

	callbackUrl, err := baseUrl.Parse("/enduser/callback")
	if err != nil {
		return nil, err
	}

	config := &oauth2.Config{
		ClientID: CLIENT_ID,
		Endpoint: oauth2.Endpoint {
			AuthURL: authUrl.String(),
			TokenURL: tokenUrl.String(),
		},
		RedirectURL: callbackUrl.String(),
		Scopes: []string{"openid", "profile", "email", "okta.users.read.self",
			"okta.users.manage.self", "okta.internal.enduser.read",
			"okta.internal.enduser.manage", "okta.enduser.dashboard.read",
			"okta.enduser.dashboard.manage"},
	}

	verifier := oauth2.GenerateVerifier()
	url := config.AuthCodeURL("state", 
		oauth2.SetAuthURLParam("nonce", "QWqTSVTcG2NgnNh6UVShUauVsvCEHFBQXIULeZSGRzyTQKMAvFdDavwtPwroHavT"),
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

func main() {
	rawUrl := flag.String("url", "", "The base URL for the Okta instance")
	username := flag.String("username", "", "The Okta username")
	password := flag.String("password", "", "The Okta password")

	flag.Parse()

	if rawUrl == nil || username == nil || password == nil {
		panic("Failed to provide correct commands")
	}

	baseUrl, err := url.Parse(*rawUrl)
	if err != nil {
		panic(err)
	}

	client, err := NewCookieJarClient()
	if err != nil {
		panic(err)
	}

	err = getSidForClient(client, baseUrl, *username, *password)
	if err != nil {
		panic(err)
	}

	token, err := getOauthToken(client, baseUrl)
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
