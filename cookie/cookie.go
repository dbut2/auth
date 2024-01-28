package cookie

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"

	"github.com/dbut2/auth/auth"
	"github.com/dbut2/auth/models"
)

type Cookies interface {
	GetUser(c *gin.Context) (*models.User, error)
	StoreUser(c *gin.Context, user *models.User) error
}

type DefaultCookies struct {
	issuer auth.Issuer
}

var _ Cookies = new(DefaultCookies)

func NewDefaultCookies(issuer auth.Issuer) *DefaultCookies {
	return &DefaultCookies{issuer: issuer}
}

func (d DefaultCookies) GetUser(c *gin.Context) (*models.User, error) {
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

	return &models.User{ID: id}, nil
}

func (d DefaultCookies) StoreUser(c *gin.Context, user *models.User) error {
	subject := strconv.Itoa(user.ID)
	token, err := d.issuer.Issue(c, subject)
	if err != nil {
		return err
	}

	encodedToken := base64.RawStdEncoding.EncodeToString([]byte(token))
	c.SetCookie("daid", encodedToken, 86400*7, "", "", false, true)

	return nil
}
