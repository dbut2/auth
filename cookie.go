package main

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

type Cookies interface {
	GetUser(c *gin.Context) (*User, error)
	StoreUser(c *gin.Context, user *User) error
}

type defaultCookies struct {
	issuer Issuer
}

var _ Cookies = new(defaultCookies)

func newDefaultCookies(issuer Issuer) *defaultCookies {
	return &defaultCookies{issuer: issuer}
}

func (d defaultCookies) GetUser(c *gin.Context) (*User, error) {
	encodedToken, err := c.Cookie("daid")
	if errors.Is(err, http.ErrNoCookie) {
		return nil, errors.New("cookie not found")
	}
	if err != nil {
		return nil, err
	}

	bytes, err := base64.RawStdEncoding.DecodeString(encodedToken)
	if err != nil {
		return nil, err
	}

	token, err := d.issuer.Verify(c, string(bytes))
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("not map claims")
	}

	subject := claims["sub"].(string)
	id, err := strconv.Atoi(subject)
	if err != nil {
		return nil, err
	}

	return &User{ID: id}, nil
}

func (d defaultCookies) StoreUser(c *gin.Context, user *User) error {
	subject := strconv.Itoa(user.ID)
	token, err := d.issuer.Issue(c, subject)
	if err != nil {
		return err
	}

	encodedToken := base64.RawStdEncoding.EncodeToString([]byte(token))
	c.SetCookie("daid", encodedToken, 86400*7, "", "", false, true)

	return nil
}
