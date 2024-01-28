package main

import (
	"bytes"
	"context"
	"embed"
	_ "embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/dbut2/auth/cookie"
	"github.com/dbut2/auth/crypto"
	"github.com/dbut2/auth/models"
	"github.com/dbut2/auth/providers"
)

type Providers map[string]Provider

type Provider struct {
	name     string
	oauth2   *oauth2.Config
	identity providers.IdentityProvider
}

func (p Providers) RedirectMap(state string) map[string]string {
	m := make(map[string]string, len(p))

	for name, provider := range p {
		m[name] = provider.oauth2.AuthCodeURL(state)
	}

	return m
}

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

	jwks, err := crypto.GenerateJwks(ctx, as.signer)
	if err != nil {
		panic(err.Error())
	}

	t, err := as.preprocessTemplate()
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

		c.HTML(http.StatusOK, "login", gin.H{"State": state})

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
		c.Redirect(http.StatusTemporaryRedirect, "/dashboard")
	})
	e.GET("/dashboard", func(c *gin.Context) {
		fmt.Println("cookies", len(c.Request.Cookies()))
		for _, cookie := range c.Request.Cookies() {
			fmt.Println(*cookie)
		}
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

//go:embed html/*.html
//go:embed html/*/*.html
var htmlFiles embed.FS

func (a *AuthService) preprocessTemplate() (*template.Template, error) {
	t, err := template.ParseFS(htmlFiles, "html/*.html", "html/*/*.html")
	if err != nil {
		return nil, err
	}

	redirectMap := a.providers.RedirectMap("{{ .State }}")

	redirectKeys := make([]string, 0, len(redirectMap))
	for key := range redirectMap {
		redirectKeys = append(redirectKeys, key)
	}
	slices.Sort(redirectKeys)

	signins := &bytes.Buffer{}
	for _, provider := range redirectKeys {
		err = t.ExecuteTemplate(signins, provider+"-signin.html", gin.H{"Link": template.HTML(redirectMap[provider])})
		if err != nil {
			return nil, err
		}
	}

	login := &bytes.Buffer{}
	err = t.ExecuteTemplate(login, "login.html", gin.H{"SignIns": template.HTML(signins.String())})
	if err != nil {
		return nil, err
	}

	loginTemplate := strings.ReplaceAll(login.String(), "%7B%7B&#43;.State&#43;%7D%7D", "{{ .State }}") // todo: there's probably a better way to do this
	return template.New("login").Parse(loginTemplate)
}

func Error(c *gin.Context, err error) {
	c.String(http.StatusInternalServerError, "Something went wrong!")

}

func (a *AuthService) Redirect(c *gin.Context) {
	pp := c.Param("provider")

	code := c.Query("code")
	state := c.Query("state")

	user, err := a.Take(c, pp, code)
	if err != nil {
		c.Error(err)
		Error(c, err)
		return
	}

	code, err = a.GenerateCode(c, user)
	if err != nil {
		c.Error(err)
		Error(c, err)
		return
	}

	if state == "no-state" {
		state = "/code"
	}

	u, err := url.Parse(state)
	if err != nil {
		c.Status(http.StatusOK)
		return
	}

	q := u.Query()
	q.Add("code", code)
	u.RawQuery = q.Encode()

	c.Redirect(http.StatusTemporaryRedirect, u.String())
}

// Take will swap a code for a token and return a User, creating one if not exists
func (a *AuthService) Take(ctx context.Context, provider string, code string) (*models.User, error) {
	p := a.providers[provider]

	token, err := p.oauth2.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	identity, err := p.identity(ctx, token)
	if err != nil {
		return nil, err
	}

	user, err := a.store.GetUser(ctx, provider, identity)
	if err != nil {
		return nil, err
	}

	if user == nil {
		user, err = a.store.CreateUser(ctx)
		if err != nil {
			return nil, err
		}
	}

	err = a.store.StoreToken(ctx, user, provider, identity, token)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (a *AuthService) GenerateCode(ctx context.Context, user *models.User) (string, error) {
	uid := uuid.New().String()

	err := a.store.StoreCode(ctx, user, uid)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString([]byte(uid)), nil
}

type AuthService struct {
	address string

	providers Providers
	signer    crypto.Signer
	encrypter crypto.Encrypter
	store     Store
	cookies   cookie.Cookies
}
