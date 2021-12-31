package main

import (
	"github.com/erikprogramador/go-jwt-authentication-example/handlers"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()
	r := gin.Default()

	r.GET("/", handlers.Home)
	r.POST("/register", handlers.Register)
	r.POST("/authenticate", handlers.Authenticate)
	r.GET("/me", handlers.Me)
	r.GET("/users", handlers.Users) // Authenticated URI. Just for test authentication

	r.Run() // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}
