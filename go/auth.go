package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dbut2/auth/go/cookie"
	"github.com/dbut2/auth/go/crypto"
	"github.com/dbut2/auth/go/models"
	"github.com/dbut2/auth/go/providers"
	"github.com/dbut2/auth/go/store"
	"github.com/dbut2/auth/html"
	"github.com/dbut2/auth/static"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	ctx := context.Background()

	config, err := ConfigFromFile("/config/config.yaml")
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
		bytes, err := static.Files.ReadFile(file)
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

func (a *AuthService) preprocessTemplate() (*template.Template, error) {
	t, err := template.ParseFS(html.Files, "*.html", "*/*.html")
	if err != nil {
		return nil, err
	}

	lm := linkMap(a.providers, "{{ .State }}")

	redirectKeys := make([]string, 0, len(lm))
	for key := range lm {
		redirectKeys = append(redirectKeys, key)
	}
	slices.Sort(redirectKeys)

	signins := &bytes.Buffer{}
	for _, provider := range redirectKeys {
		err = t.ExecuteTemplate(signins, provider+"-signin.html", gin.H{"Link": template.HTML(lm[provider])})
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

func linkMap(ps providers.Providers, state string) map[string]string {
	lm := map[string]string{}
	for _, p := range ps {
		lm[p.Name] = p.OAuth2.AuthCodeURL(state)
	}
	return lm
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

	token, err := p.OAuth2.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	identity, err := p.Identity(ctx, token)
	if err != nil {
		return nil, err
	}

	user, err := a.store.GetUser(ctx, provider, identity)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if errors.Is(err, store.ErrNotFound) || user == nil {
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

	providers providers.Providers
	signer    crypto.Signer
	encrypter crypto.Encrypter
	store     store.Store
	cookies   cookie.Cookies
}
