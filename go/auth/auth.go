package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/dbut2/auth/go/cookie"
	"github.com/dbut2/auth/go/crypto"
	"github.com/dbut2/auth/go/issuer"
	"github.com/dbut2/auth/go/models"
	"github.com/dbut2/auth/go/providers"
	"github.com/dbut2/auth/go/store"
	"github.com/dbut2/auth/html"
	"github.com/dbut2/auth/static"
)

func (a *AuthService) Handlers(e *gin.Engine) {
	t, err := a.preprocessTemplate()
	if err != nil {
		panic(err.Error())
	}

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
	e.NoRoute(func(c *gin.Context) {
		c.Redirect(http.StatusTemporaryRedirect, "/error/404")
	})
	e.NoMethod(func(c *gin.Context) {
		c.Redirect(http.StatusTemporaryRedirect, "/error/405")
	})
	e.GET("/error/:code", func(c *gin.Context) {
		a.ErrorHandler(c, titles, messages)
	})
	e.GET("/error", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/error/500")
	})
	e.GET("/static/:file", a.StaticFileHandler)
	e.GET("/.well-known/jwks.json", a.JwksHandler)
	e.GET("/", a.RootHandler)
	e.GET("/redirect/:provider", a.Redirect)
	e.GET("/code", a.CodeHandler)
	e.GET("/dashboard", a.HandlerDashboard)
	e.GET("/trade/:code", a.TradeHandler)
}

func (a *AuthService) TradeHandler(c *gin.Context) {
	code := c.Param("code")

	user, err := a.store.GetCodeUser(c, code)

	if err != nil {
		panic(err.Error())
	}
	if user == nil {
		c.String(http.StatusNotFound, "User not found")
		return
	}

	token, err := a.issuer.Issue(c, strconv.Itoa(user.ID))
	if err != nil {
		panic(err.Error())
	}

	c.String(http.StatusOK, token)
}

func (a *AuthService) StaticFileHandler(c *gin.Context) {
	file := c.Param("file")
	bytes, err := static.Files.ReadFile(file)
	if err != nil {
		panic(err.Error())
	}
	c.String(http.StatusOK, string(bytes))
}

func (a *AuthService) ErrorHandler(c *gin.Context, titles map[string]string, messages map[string]string) {
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
}

func (a *AuthService) JwksHandler(c *gin.Context) {
	c.JSON(http.StatusOK, a.jwks)
}

func (a *AuthService) RootHandler(c *gin.Context) {
	state := c.Query("redirect_uri")
	if state == "" {
		state = "no-state"
	}

	c.HTML(http.StatusOK, "login", gin.H{"State": state})
}

func (a *AuthService) CodeHandler(c *gin.Context) {
	code := c.Query("code")
	rawCode, err := base64.RawStdEncoding.DecodeString(code)
	if err != nil {
		panic(err.Error())
	}
	user, err := a.store.GetCodeUser(c, string(rawCode))
	if err != nil {
		panic(err.Error())
	}
	if user == nil {
		panic("no user")
	}
	err = a.cookies.StoreUser(c, user)
	if err != nil {
		panic(err.Error())
	}
	c.Redirect(http.StatusTemporaryRedirect, "/dashboard")
}

func (a *AuthService) HandlerDashboard(c *gin.Context) {
	user, err := a.cookies.GetUser(c)
	if err != nil {
		panic(err.Error())
	}
	if user == nil {
		c.String(http.StatusNotFound, "User not found")
		return
	}
	c.String(http.StatusOK, strconv.Itoa(user.ID))
}

func (a *AuthService) preprocessTemplate() (*template.Template, error) {
	rawT, err := template.ParseFS(html.Files, "*.html", "*/*.html")
	if err != nil {
		return nil, err
	}

	lm := linkMap(a.providers, "{{ .State }}")

	redirectKeys := make([]string, 0, len(lm))
	for key := range lm {
		redirectKeys = append(redirectKeys, key)
	}
	slices.Sort(redirectKeys)

	t, err := rawT.Clone()
	if err != nil {
		return nil, err
	}

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
	return rawT.New("login").Parse(loginTemplate)
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
	issuer    issuer.Issuer
	store     store.Store
	cookies   cookie.Cookies

	jwks jwk.Set
}
