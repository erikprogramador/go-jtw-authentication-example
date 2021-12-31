package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/dgrijalva/jwt-go"
	"github.com/erikprogramador/go-jwt-authentication-example/entity"
	"github.com/erikprogramador/go-jwt-authentication-example/infra"
	"github.com/erikprogramador/go-jwt-authentication-example/response"
	"github.com/gin-gonic/gin"
)

func Register(c *gin.Context) {
	var user entity.User
	err := c.BindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "The given data was invalid.",
			"error":   err.Error(),
		})
		return
	}
	if user.Name == "" || user.Email == "" || user.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Please fill the required fields (name, email, password).",
		})
		return
	}
	connection := infra.CreateConnection()
	defer connection.Close()
	stmt, err := connection.Prepare("SELECT * FROM users WHERE email = ?")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "OPS! WE HAVE A PROBLEM ON OUR SERVER. PLEASE TRY AGAIN LATER.",
			"error":   err.Error(),
		})
		return
	}
	var foundUser entity.User
	stmt.QueryRow(user.Email).Scan(&foundUser.Email)
	if foundUser.Email != "" {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": "The given email is already registered.",
		})
		return
	}
	stmt, err = connection.Prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "OPS! WE HAVE A PROBLEM ON OUR SERVER. PLEASE TRY AGAIN LATER.",
			"error":   err.Error(),
		})
		return
	}
	_, err = stmt.Exec(user.Name, user.Email, user.EncryptedPassword())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "OPS! WE HAVE A PROBLEM ON OUR SERVER. PLEASE TRY AGAIN LATER.",
			"error":   err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Register created with success!",
	})
}

func Authenticate(c *gin.Context) {
	var user entity.User
	err := c.BindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "The given data was invalid.",
			"error":   err.Error(),
		})
		return
	}
	if user.Email == "" || user.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Please fill the required fields (email, password).",
		})
		return
	}
	connection := infra.CreateConnection()
	defer connection.Close()
	stmt, err := connection.Prepare("SELECT * FROM users WHERE email = ?")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "OPS! WE HAVE A PROBLEM ON OUR SERVER. PLEASE TRY AGAIN LATER.",
			"error":   err.Error(),
		})
		return
	}
	var foundUser entity.User
	stmt.QueryRow(user.Email).Scan(&foundUser.ID, &foundUser.Name, &foundUser.Email, &foundUser.Password)
	if foundUser.Email == "" {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": "The given email does not exist.",
		})
		return
	}
	password := foundUser.CheckPassword(user.Password)
	if !password {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": "The given password is invalid.",
		})
		return
	}
	token, err := infra.CreateToken(foundUser.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "OPS! WE HAVE A PROBLEM ON OUR SERVER. PLEASE TRY AGAIN LATER.",
			"error":   err.Error(),
		})
		return
	}
	c.JSON(200, gin.H{
		"token": token,
	})
}

func Me(c *gin.Context) {
	tokenString := infra.ExtractToken(c.Request)
	token, err := infra.VerifyToken(tokenString)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid Token",
			"error":   err.Error(),
		})
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": "The given token is not valid",
		})
		return
	}
	userId, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": "The given token is not valid",
			"error":   err.Error(),
		})
		return
	}
	connection := infra.CreateConnection()
	defer connection.Close()
	stmt, err := connection.Prepare("SELECT id, name, email FROM users WHERE id = ?")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "OPS! WE HAVE A PROBLEM ON OUR SERVER. PLEASE TRY AGAIN LATER.",
			"error":   err.Error(),
		})
		return
	}
	var foundUser entity.User
	stmt.QueryRow(userId).Scan(&foundUser.ID, &foundUser.Name, &foundUser.Email)
	if foundUser.ID == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"message": "The given user does not exist.",
		})
		return
	}
	c.JSON(200, &response.ResponseUser{
		ID:    foundUser.ID,
		Name:  foundUser.Name,
		Email: foundUser.Email,
	})
}
