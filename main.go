package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

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

func NewCookieJarClient() (*http.Client, error) {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: nil})
	if err != nil {
		return nil, err
	}

	return &http.Client{ Jar: jar }, nil

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
	instanceName := options.instanceName
	appId := options.appId

	client, err := NewCookieJarClient()
	if err != nil {
		panic(err)
	}

	err = getSidForClient(client, baseUrl, username, password)
	if err != nil {
		panic(err)
	}

	passwordUrl, err := baseUrl.Parse(fmt.Sprintf("/api/plugin/2/app/%s/%s/flow", instanceName, appId))
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest("GET", passwordUrl.String(), nil)
	if err != nil {
		panic(err)
	}

	req.Header.Add("Accept", "application/json")

	resp, err := client.Do(req)
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
