package main

import (
	"context"
	"crypto/rsa"
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"math/big"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"golang.org/x/oauth2"
)

type Providers map[string]Provider

type Provider struct {
	name     string
	oauth2   *oauth2.Config
	identity IdentityProvider
}

func (p Providers) RedirectMap(state string) map[string]string {
	m := make(map[string]string, len(p))

	for name, provider := range p {
		m[name] = provider.oauth2.AuthCodeURL(state)
	}

	return m
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	ctx := context.Background()

	configSecret := os.Getenv("CONFIG_SECRET")
	config, err := ConfigFromSecret(ctx, configSecret)
	if err != nil {
		panic(err.Error())
	}

	as, err := NewService(config)

	pub, err := as.signer.PublicKey(ctx)
	if err != nil {
		panic(err.Error())
	}

	jwks, err := getJwks(pub)
	if err != nil {
		panic(err.Error())
	}

	t, err := template.New("login").Parse(login)
	if err != nil {
		panic(err.Error())
	}

	e := gin.Default()
	e.SetHTMLTemplate(t)

	e.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Hello, world!")
	})
	e.GET("/.well-known/jwks.json", func(c *gin.Context) {
		c.JSON(http.StatusOK, jwks)
	})
	e.GET("/login", func(c *gin.Context) {
		state := c.Query("redirect_uri")
		if state == "" {
			state = "no-state"
		}

		c.HTML(http.StatusOK, "login", as.providers.RedirectMap(state))
	})
	e.GET("/redirect/:provider", as.Redirect)

	err = http.ListenAndServe(":"+port, e)
	if err != nil {
		panic(err.Error())
	}
}

//go:embed login.html
var login string

func getJwks(pem []byte) (jwk.Set, error) {
	rsaPublicKey, _, err := jwk.DecodePEM(pem)
	if err != nil {
		return nil, err
	}
	key, err := jwk.FromRaw(rsaPublicKey)
	if err != nil {
		return nil, err
	}

	set := jwk.NewSet()
	err = set.AddKey(key)
	if err != nil {
		return nil, err
	}
	return set, nil
}

// verifyToken verifies the token using the JWKS endpoint
func verifyToken(jwksUrl string, myToken string) (*jwt.Token, error) {
	resp, err := http.Get(jwksUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	fmt.Println(string(bytes))
	jwks, err := jwk.Parse(bytes)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(myToken, func(token *jwt.Token) (interface{}, error) {
		k, _ := jwks.Key(0)

		pk := k.(jwk.RSAPublicKey)

		pk2 := &rsa.PublicKey{
			N: big.NewInt(0).SetBytes(pk.N()),
			E: int(big.NewInt(0).SetBytes(pk.E()).Int64()),
		}

		return pk2, nil
	})

	if err != nil {
		return nil, err
	}

	return token, nil
}

type AuthService struct {
	address string

	providers Providers
	signer    Signer
	encrypter Encrypter
	store     Store
}
