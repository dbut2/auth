package client

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type Client struct {
	host string
}

func New(host string) *Client {
	return &Client{host: host}
}

func (c *Client) Redirect(redirect string) string {
	u, err := url.Parse(c.host)
	if err != nil {
		panic(err.Error())
	}

	q := u.Query()
	q.Add("redirect_uri", redirect)
	u.RawQuery = q.Encode()

	return u.String()
}

func (c *Client) Trade(code string) string {
	decodedCode, err := base64.RawStdEncoding.DecodeString(code)
	if err != nil {
		panic(err.Error())
	}

	u, err := url.Parse(c.host)
	if err != nil {
		panic(err.Error())
	}

	u = u.JoinPath(fmt.Sprintf("/trade/%s", decodedCode))

	resp, err := http.Get(u.String())
	if err != nil {
		panic(err.Error())
	}

	defer resp.Body.Close()
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err.Error())
	}

	return string(bytes)
}

func (c *Client) TradeCookie(code string) *http.Cookie {
	token := c.Trade(code)
	return &http.Cookie{
		Name:     "daid",
		Value:    url.QueryEscape(token),
		Secure:   false,
		HttpOnly: true,
	}
}
