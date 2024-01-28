package main

import (
	"bytes"
	"context"
	"embed"
	_ "embed"
	"encoding/base64"
	"html/template"
	"net/http"
	"os"
	"strconv"

	"github.com/dbut2/auth/crypto"
	"github.com/gin-gonic/gin"
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

//go:embed html/*.html
//go:embed html/*/*.html
var htmlFiles embed.FS

//go:embed static/*
var staticFiles embed.FS

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

	as, err := NewService(ctx, config)
	if err != nil {
		panic(err.Error())
	}

	jwks, err := getJwks(ctx, as.signer)
	if err != nil {
		panic(err.Error())
	}

	t, err := template.ParseFS(htmlFiles, "html/*.html", "html/*/*.html")
	if err != nil {
		panic(err.Error())
	}

	e := gin.Default()
	e.SetHTMLTemplate(t)

	titles := map[string]string{
		"404": "Page not found",
		"418": "I'm a teapot",
		"500": "Server error",
	}
	messages := map[string]string{
		"404": "Sorry, we couldn't find the page you're looking for.",
		"418": "may be short and stout",
		"500": "Sorry, something went wrong while trying to process your request.",
	}
	e.GET("/error/:code", func(c *gin.Context) {
		code := c.Param("code")

		title, ok := titles[code]
		if !ok {
			title = titles["500"]
		}
		message, ok := messages[code]
		if !ok {
			message = messages["500"]
		}

		c.HTML(http.StatusOK, "error.html", gin.H{
			"Code":    code,
			"Title":   title,
			"Message": message,
		})
	})
	e.GET("/error", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/error/500")
	})

	e.GET("/static/:file", func(c *gin.Context) {
		file := c.Param("file")
		bytes, err := staticFiles.ReadFile("static/" + file)
		if err != nil {
			panic(err.Error())
		}
		c.String(http.StatusOK, string(bytes))
	})
	e.GET("/.well-known/jwks.json", func(c *gin.Context) {
		c.JSON(http.StatusOK, jwks)
	})
	e.GET("/", func(c *gin.Context) {
		state := c.Query("redirect_uri")
		if state == "" {
			state = "no-state"
		}

		redirectMap := as.providers.RedirectMap(state)
		signins := &bytes.Buffer{}
		for _, p := range as.providers {

			err = t.ExecuteTemplate(signins, p.name+"-signin.html", gin.H{"Link": redirectMap[p.name]})
			if err != nil {
				panic(err.Error())
			}
		}

		c.HTML(http.StatusOK, "login.html", gin.H{"SignIns": template.HTML(signins.String())})
	})
	e.GET("/redirect/:provider", as.Redirect)
	e.GET("/code", func(c *gin.Context) {
		code := c.Query("code")
		rawCode, err := base64.RawStdEncoding.DecodeString(code)
		if err != nil {
			panic(err.Error())
		}
		user, err := as.store.GetCodeUser(c, string(rawCode))
		if err != nil {
			panic(err.Error())
		}
		if user == nil {
			panic("no user")
		}
		err = as.cookies.StoreUser(c, user)
		if err != nil {
			panic(err.Error())
		}
		c.Status(http.StatusOK)
	})
	e.GET("/user", func(c *gin.Context) {
		user, err := as.cookies.GetUser(c)
		if err != nil {
			panic(err.Error())
		}
		if user == nil {
			c.String(http.StatusNotFound, "User not found")
			return
		}
		c.String(http.StatusOK, strconv.Itoa(user.ID))
	})

	err = http.ListenAndServe(":"+port, e)
	if err != nil {
		panic(err.Error())
	}
}

func getJwks(ctx context.Context, signer crypto.Signer) (jwk.Set, error) {
	pem, kid, err := signer.PublicKey(ctx)
	if err != nil {
		return nil, err
	}

	rsaPublicKey, _, err := jwk.DecodePEM(pem)
	if err != nil {
		return nil, err
	}
	key, err := jwk.FromRaw(rsaPublicKey)
	if err != nil {
		return nil, err
	}

	err = key.Set("kid", kid)
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

type AuthService struct {
	address string

	providers Providers
	signer    crypto.Signer
	encrypter crypto.Encrypter
	store     Store
	cookies   Cookies
}
