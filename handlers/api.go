package handlers

import "github.com/gin-gonic/gin"

func Home(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "You are in a no where place!",
	})
}
