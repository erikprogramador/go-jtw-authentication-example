package handlers

import (
	"net/http"

	"github.com/erikprogramador/go-jwt-authentication-example/infra"
	"github.com/erikprogramador/go-jwt-authentication-example/response"
	"github.com/gin-gonic/gin"
)

func Users(c *gin.Context) {
	tokenString := infra.ExtractToken(c.Request)
	_, err := infra.VerifyToken(tokenString)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid Token",
			"error":   err.Error(),
		})
		return
	}
	connection := infra.CreateConnection()
	defer connection.Close()
	stmt, err := connection.Prepare("SELECT id, name, email FROM users")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "OPS! WE HAVE A PROBLEM ON OUR SERVER. PLEASE TRY AGAIN LATER.",
			"error":   err.Error(),
		})
		return
	}
	rows, err := stmt.Query()
	defer rows.Close()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "OPS! WE HAVE A PROBLEM ON OUR SERVER. PLEASE TRY AGAIN LATER.",
			"error":   err.Error(),
		})
		return
	}
	var users []response.ResponseUser
	for rows.Next() {
		var user response.ResponseUser
		err := rows.Scan(&user.ID, &user.Name, &user.Email)
		if err != nil {
			panic(err) // Error related to the scan
		}
		users = append(users, user)
	}
	c.JSON(200, users)
}
