package providers

import (
	"context"
	"net/http"

	"github.com/google/go-github/v58/github"
	"github.com/huandu/facebook"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
	"google.golang.org/api/people/v1"
)

// IdentityProvider should return a deterministic object for a user
type IdentityProvider func(ctx context.Context, token *oauth2.Token) (any, error)

func GetFacebookIdentity(clientID, clientSecret string) IdentityProvider {
	client := facebook.New(clientID, clientSecret)
	client.EnableAppsecretProof = true

	return func(ctx context.Context, token *oauth2.Token) (any, error) {
		session := client.Session(token.AccessToken)
		session.AppsecretProof()
		return session.User()
	}
}

func GitHubIdentity(ctx context.Context, token *oauth2.Token) (any, error) {
	client := github.NewClient(http.DefaultClient).WithAuthToken(token.AccessToken)
	user, _, err := client.Users.Get(ctx, "")
	if err != nil {
		return nil, err
	}
	return user.GetID(), nil
}

func GoogleIdentity(ctx context.Context, token *oauth2.Token) (any, error) {
	httpClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
	client, err := people.NewService(ctx, option.WithHTTPClient(httpClient))
	if err != nil {
		return nil, err
	}
	person, err := client.People.Get("people/me").PersonFields("names").Do()
	if err != nil {
		return nil, err
	}
	return person.ResourceName, nil
}
