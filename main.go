package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type ResponseUser struct {
	ID    uint64 `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type User struct {
	ID       uint64 `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (u User) EncryptedPassword() string {
	password := []byte(u.Password)

	hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	u.Password = string(hashedPassword)
	return u.Password
}

func (u User) CheckPassword(pass string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(pass))
	if err != nil {
		return false
	}
	return true
}

func CreateToken(userid uint64) (string, error) {
	var err error
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_id"] = userid
	atClaims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, err := at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return "", err
	}
	return token, nil
}

func ExtractToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

func VerifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := ExtractToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func main() {
	os.Setenv("ACCESS_SECRET", "go_jwt_authentication_example") //this should be in an env file
	r := gin.Default()

	r.GET("/", home)
	r.POST("/register", register)
	r.POST("/authenticate", authenticate)
	r.GET("/me", me)
	r.GET("/users", users) // Authenticated URI. Just for test authentication

	r.Run() // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}

func CreateConnection() *sql.DB {
	db, err := sql.Open("mysql", "root:@/authentication_jwt_go")
	if err != nil {
		panic(err)
	}

	return db
}

func home(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "You are in a no where place!",
	})
}

func register(c *gin.Context) {
	var user User
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
	connection := CreateConnection()
	defer connection.Close()
	stmt, err := connection.Prepare("SELECT * FROM users WHERE email = ?")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "OPS! WE HAVE A PROBLEM ON OUR SERVER. PLEASE TRY AGAIN LATER.",
			"error":   err.Error(),
		})
		return
	}
	var foundUser User
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

func authenticate(c *gin.Context) {
	var user User
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
	connection := CreateConnection()
	defer connection.Close()
	stmt, err := connection.Prepare("SELECT * FROM users WHERE email = ?")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "OPS! WE HAVE A PROBLEM ON OUR SERVER. PLEASE TRY AGAIN LATER.",
			"error":   err.Error(),
		})
		return
	}
	var foundUser User
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
	token, err := CreateToken(foundUser.ID)
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

func me(c *gin.Context) {
	token, err := VerifyToken(c.Request)
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
	connection := CreateConnection()
	defer connection.Close()
	stmt, err := connection.Prepare("SELECT id, name, email FROM users WHERE id = ?")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "OPS! WE HAVE A PROBLEM ON OUR SERVER. PLEASE TRY AGAIN LATER.",
			"error":   err.Error(),
		})
		return
	}
	var foundUser User
	stmt.QueryRow(userId).Scan(&foundUser.ID, &foundUser.Name, &foundUser.Email)
	if foundUser.ID == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"message": "The given user does not exist.",
		})
		return
	}
	c.JSON(200, &ResponseUser{
		ID:    foundUser.ID,
		Name:  foundUser.Name,
		Email: foundUser.Email,
	})
}

func users(c *gin.Context) {
	_, err := VerifyToken(c.Request)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid Token",
			"error":   err.Error(),
		})
		return
	}
	connection := CreateConnection()
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
	var users []ResponseUser
	for rows.Next() {
		var user ResponseUser
		err := rows.Scan(&user.ID, &user.Name, &user.Email)
		if err != nil {
			panic(err) // Error related to the scan
		}
		users = append(users, user)
	}
	c.JSON(200, users)
}
