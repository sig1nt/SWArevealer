package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
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


func main() {
	rawUrl := flag.String("url", "", "The Okta URL to get the password for")
	sid := flag.String("sid", "", "The Okta SID")

	flag.Parse()

	if rawUrl == nil || sid == nil {
		panic("Failed to provide correct commands")
	}

	parsedUrl, err := url.Parse(*rawUrl)
	if err != nil {
		panic(err)
	}

	pathParts := strings.Split(strings.Trim(parsedUrl.Path, "/"), "/")

	if len(pathParts) != 4 {
		fmt.Println(pathParts)
		panic("Improperly formatted URL")
	}

	parsedUrl.Path = fmt.Sprintf("/api/plugin/2/app/%s/%s/flow", pathParts[1], pathParts[2])

	req, err := http.NewRequest("GET", parsedUrl.String(), nil)
	if err != nil {
		panic(err)
	}

	req.Header.Add("Accept", "application/json")
	req.AddCookie(&http.Cookie{Name: "sid", Value:*sid})

	resp, err := http.DefaultClient.Do(req)
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
