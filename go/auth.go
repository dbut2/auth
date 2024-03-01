package main

import (
	"context"
	_ "embed"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/dbut2/auth/go/auth"
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

	as, err := auth.NewService(ctx, config)
	if err != nil {
		panic(err.Error())
	}

	e := gin.Default()
	as.Handlers(e)

	err = http.ListenAndServe(":"+port, e)
	if err != nil {
		panic(err.Error())
	}
}
