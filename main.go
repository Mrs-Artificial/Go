// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name LoginToken
package main

//db password airista123
//use password blakekatz - blakekatz123

import (
	docs "blake/rest/docs"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"
	"unicode"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"

	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

var db *sqlx.DB
var err error

var MySecretKeyForJWT = "secretkeyairista"
var jwtKey = []byte(MySecretKeyForJWT)

type Claims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

type User struct {
	ID             string `json:"id" db:"id"`
	Name           string `json:"name" db:"name"`
	Lock           bool   `json:"locked" db:"lock"`
	Employee       bool   `json:"employee" db:"employee" `
	Age            int    `json:"age" db:"age"`
	Email          string `json:"email" db:"email"`
	Password       string `json:"password" db:"password"`
	LicenseVersion string `json:"license_version" db:"version"`
}

type AddUserRequest struct {
	Name     string `json:"name" binding:"required"`
	Age      int    `json:"age" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Version  string `json:"version" binding:"required"`
	Employee bool   `json:"employee"`
	Password string `json:"password" binding:"required"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type DBGetType int

const (
	ID DBGetType = iota + 1
	Name
	Email
	Employee
	Age
	LicenseVersion
)

/*var allUsers = []User{

	{Name: "John Doe", Lock: false, Age: 30, Email: "john@example.com", LicenseVersion: "1.1.2", Employee: true},
	{Name: "Jane Doe", Lock: true, Age: 28, Email: "jane@example.com", LicenseVersion: "1.0.1", Employee: false},
	{Name: "Alice Flick", Lock: false, Age: 35, Email: "alicef@example.com", LicenseVersion: "1.2.0", Employee: true},
	{Name: "Chum Broome", Lock: false, Age: 29, Email: "chumb@example.com", LicenseVersion: "1.0.4", Employee: true},
	{Name: "Donny Rodgers", Lock: false, Age: 29, Email: "donrodg@example.com", LicenseVersion: "1.0.2", Employee: false},
	{Name: "Lazlow Gerdie", Lock: false, Age: 21, Email: "lazgerd@example.com", LicenseVersion: "1.1.0", Employee: false},
	{Name: "Oswald Effenberger", Lock: false, Age: 23, Email: "oseff@example.com", LicenseVersion: "2.3.1", Employee: true},
	{Name: "Stephen Allen", Lock: true, Age: 22, Email: "stepha@example.com", LicenseVersion: "1.5.2", Employee: false},
}*/

// @title           User Managment Rest API
// @version         1.0
// @description     Test work for managing users
// @termsOfService  http://swagger.io/terms/

// @contact.name   BlakeKatz
// @contact.email  blake.katz@airista.com

// @host      localhost:8080

func main() {

	db, err = sqlx.Connect("mysql", "root:airista123@tcp(localhost:3306)/users")

	if err != nil {
		panic("Failed to connect to database")
	} else {
		fmt.Println("sucessfully connected to database")
	}
	defer db.Close()

	r := gin.Default()
	docs.SwaggerInfo.BasePath = ""

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))

	r.GET("/", homeJson)

	r.POST("/login", login)

	protected := r.Group("/")
	protected.Use(authMiddleware())
	{
		protected.DELETE("/remubyid/:UUID", jsonremubyid)
		protected.POST("/adduser", addJsonUser)
		protected.POST("/lockbyid/:UUID", lockUserJson)
		protected.DELETE("/remlocked", deleteAllLockedUsersJson)
		protected.GET("/users", userJson)
		protected.GET("/users/employees", employeeJson)
		protected.GET("/users/locked", getLockedUserJson)
	}

	r.Run("localhost:8080")
}

// @Summary      Adds a user based on the provided JSON body
// @Description  Adds a user based on the provided JSON body
// @Tags         Users
// @Produce      json
// @Security     ApiKeyAuth
// @Param        user body AddUserRequest true "User data"
// @Success      200  {string}  string
// @Failure      400  {string}  string
// @Router       /adduser [post]
func addJsonUser(c *gin.Context) {
	var req AddUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !isPassValid(req.Password) {
		c.JSON(400, gin.H{"error": "Password does not meet requirements. Must have at least 12 characters, 3 numbers and 2 symbols"})
		return
	}

	if isEmailValid(req.Email) {
		cryPass, err2 := HashPassword(req.Password)
		if err2 != nil {
			c.JSON(500, gin.H{"error": "Password could not be hashed. Please try again later."})
			return
		}

		err := addUser(req.Name, req.Age, req.Email, req.Version, req.Employee, cryPass)
		if err != nil {
			c.JSON(500, gin.H{"error": "User could not be added"})
			fmt.Print(err)
			return
		} else {
			c.JSON(http.StatusOK, gin.H{"success": "User added successfully"})
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
	}
}

// @Summary      Removes a user based off their uuid assigned at creation
// @Description  Removes a user based off their uuid assigned at creation
// @Tags         Users
// @Security 	 ApiKeyAuth
// @Produce      json
// @Param        UUID path string true "The UUID of the user"
// @Success      200  {string}  string
// @Failure      400  {string}  string
// @Router       /remubyid/{UUID} [delete]
func jsonremubyid(c *gin.Context) {
	uuid := c.Param("UUID")
	_, err := db.Query("DELETE FROM users WHERE ID = ?", uuid)
	if err == nil {
		c.JSON(http.StatusOK, gin.H{"sucess": "User removed successfully"})
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No such user with provided uuid"})
	}

}

// @Summary      Gets all users and their subfeilds
// @Description  Gets all users and their subfeilds
// @Tags         Users
// @Security 	 ApiKeyAuth
// @Accept       json
// @Produce      json
// @Success      200  {object}  User[]
// @Router       /users [get]
func userJson(c *gin.Context) {
	var users []User
	err := db.Select(&users, "SELECT * FROM users")

	if err != nil {
		c.JSON(500, gin.H{"error": "Error retrieving users"})
		return
	}
	c.IndentedJSON(http.StatusOK, users)
}

// @Summary      Gets employees based off json boolean value
// @Description  Gets employees based off json boolean value
// @Tags         Users
// @Security 	 ApiKeyAuth
// @Accept       json
// @Produce      json
// @Success      200  {object}  User[]
// @Router       /users/employees [get]
func employeeJson(c *gin.Context) {

	users, err := getFieldFromDB(Employee, "1")

	if err != nil {
		c.JSON(500, gin.H{"error": "Error retrieving users"})
		return
	}

	c.IndentedJSON(http.StatusOK, users)
}

// @Summary      Home
// @Description  Home page
// @Tags         Main
// @Accept       json
// @Produce      json
// @Success      200  {string}  HomePage
// @Router       / [get]
func homeJson(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, gin.H{
		"Greeting":     "Welcome to the home page",
		"Verification": "Please use the /login endpoint to login with a valid email and password. This will provide you with a login key to paste at the top which gives you acess to all the methods.",
		"Information":  "You can look at all the users by going to /users, and you can look at the employees by doing /users/employees. Locked users are found with /users/locked",
		"UserCreation": "Add a new user by doing /adduser followed by paramters going in ordrer from name to password status",
		"UserDelete":   "Remove user by UUID with /remubyid and followed by the uuid as a param",
		"LockUser":     "/lockbyid followed by a uuid will lock a users account, making it impossible for them to login and removing their key validity",
	})
}

// @Summary      Gets all users if they have locked accounts
// @Description  Gets all users if they have locked accounts
// @Tags         Users
// @Security 	 ApiKeyAuth
// @Accept       json
// @Produce      json
// @Success      200  {object}  User[]
// @Router       /users/locked [get]
func getLockedUserJson(c *gin.Context) {
	var users []User
	err := db.Select(&users, "SELECT * FROM users WHERE `lock`=1")

	if err != nil {
		c.JSON(500, gin.H{"error": "Error retrieving users or none such exist"})
		return
	}

	c.IndentedJSON(http.StatusOK, users)
}

// @Summary      Toggles a users locked account status
// @Description  Toggles a users locked account status
// @Tags         Users
// @Security 	 ApiKeyAuth
// @Produce      json
// @Param        UUID path string true "The UUID of the user"
// @Success      200  {string}  string
// @Failure      400  {string}  string
// @Router       /lockbyid/{UUID} [post]
func lockUserJson(c *gin.Context) {
	uuid := c.Param("UUID")
	_, err := db.Query("UPDATE users SET `lock` = NOT `lock` WHERE ID=?", uuid)

	if err == nil {
		c.JSON(http.StatusOK, gin.H{"sucess": "User account lock status changed successfully"})

		users, err := getFieldFromDB(ID, uuid)
		if err != nil {
			c.JSON(401, gin.H{"error": "Wrong ID!"})
			return
		}
		user := users[0]
		if user.Lock {
			invalidateToken(tokenList[user.Email])
		}

	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ERROR"})
	}

}

// @Summary      Deletes all the locked users as a form of cleaning
// @Description  Deletes all the locked users as a form of cleaning
// @Tags         Users
// @Security 	 ApiKeyAuth
// @Produce      json
// @Success      200  {string}  string
// @Failure      400  {string}  string
// @Router       /remlocked [delete]
func deleteAllLockedUsersJson(c *gin.Context) {

	_, err := db.Query("DELETE FROM users WHERE `lock` = 1")
	//clear entire blacklist as there is no need to have these when all locked users are deleted
	for key := range tokenBlacklist {
		delete(tokenBlacklist, key)
	}
	if err == nil {
		c.JSON(http.StatusOK, gin.H{"sucess": "User removed successfully"})
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No such user with provided uuid"})
	}

}

// @Summary      Login user
// @Description  Login user with email and password
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        user body LoginRequest true "User Login Info"
// @Success      200  {string}  string
// @Failure      400  {string}  string
// @Router       /login [post]
func login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	users, err2 := getFieldFromDB(Email, req.Email)
	if err2 != nil {
		c.JSON(401, gin.H{"error": "Invalid email or password"})
		return
	}
	user := users[0]
	//maybe add same type implementation later, assuming that there might be 2 users with the same email

	if user.Lock {
		c.JSON(401, gin.H{"error": "User account is locked, sign in unavaible"})
		return
	}
	isValid := CheckPasswordHash(req.Password, user.Password)
	if isValid {
		c.JSON(401, gin.H{"error": "Invalid email or password"})
		return
	}

	token, err := generateToken(user.Email)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(200, gin.H{"token": token})
}

//non gin helper methods

func addUser(name string, age int, email string, licenseV string, emp bool, password string) error {
	// Prepare the SQL statement
	stmt, err := db.Prepare("INSERT INTO users (name, age, email, version, `employee`, password) VALUES (?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	// Convert boolean employee to int
	employee := 0
	if emp {
		employee = 1
	}

	// Execute the statement with user data
	_, err = stmt.Exec(name, age, email, licenseV, employee, password)
	if err != nil {
		return err
	}

	return nil

}

// Checks if a given email is valid
func isEmailValid(e string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]{5,}@[a-zA-Z0-9.\-]+\.(com|org|gov|edu|net)$`)
	return emailRegex.MatchString(e)
}
func isPassValid(s string) bool {
	chars := 0;
	numbers := 0;
	symbols := 0;
	upper := false;

	for _, c := range s {
		switch {
		case unicode.IsNumber(c):
			numbers++;
			chars++;
		case unicode.IsSymbol(c) || unicode.IsPunct(c):
			symbols++;
			chars++;
		case unicode.IsUpper(c):
			chars++;
			upper = true;
		default:
			chars++;
		}
	}
	
	if(chars >= 12 && numbers >= 3 && symbols >= 2 && upper){
		return true;

	}
	return false;


	
	
}

func getFieldFromDB(t DBGetType, value string) ([]User, error) {
	var user []User
	switch t {
	case ID:
		err := db.Select(&user, "SELECT * FROM users WHERE ID = ?", value)
		if err != nil {
			return nil, err
		}
	case Name:
		err := db.Select(&user, "SELECT * FROM users WHERE name = ?", value)
		if err != nil {
			return nil, err
		}
	case Age:
		err := db.Select(&user, "SELECT * FROM users WHERE age = ?", value)
		if err != nil {
			return nil, err
		}

	case Email:

		err := db.Select(&user, "SELECT * FROM users WHERE email = ?", value)
		if err != nil {

			return nil, err
		}
	case Employee:
		err := db.Select(&user, "SELECT * FROM users WHERE `employee`= ?", value)
		if err != nil {

			return nil, err
		}
	case LicenseVersion:
		err := db.Select(&user, "SELECT * FROM users WHERE version = ?", value)
		if err != nil {
			return nil, err
		}

	}
	return user, nil

}

//jwt

var tokenBlacklist = make(map[string]bool)
var tokenList = make(map[string]string)

func generateToken(email string) (string, error) {
	expirationTime := time.Now().Add(12 * time.Hour)
	claims := &Claims{
		Email: email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Id:        generateTokenID(), // Add a unique ID to each token
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	stringToken, _ := token.SignedString(jwtKey)

	tokenList[email] = stringToken
	return token.SignedString(jwtKey)
}

func invalidateToken(tokenString string) error {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		return errors.New("invalid token")
	}

	// Add the token's jti to the blacklist and remove it from the whitelist.
	delete(tokenList, claims.Email)
	tokenBlacklist[claims.Id] = true
	return nil
}

func validateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid || tokenBlacklist[claims.Id] {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

func generateTokenID() string {
	return strconv.FormatInt(time.Now().UnixNano(), 10)
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("LoginToken")
		if tokenString == "" {
			c.JSON(401, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}

		claims, err := validateToken(tokenString)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		c.Set("email", claims.Email)
		c.Next()
	}
}

// password incryption
func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

/*
// @Summary      Register a new user
// @Description  Register a new user with email and password
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        user body RegisterRequest true "User Registration Info"
// @Success      200  {string}  string
// @Failure      400  {string}  string
// @Router       /register [post]
func register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to hash password"})
		return
	}

	err = addUser(req.Name, req.Age, req.Email, "1.0.0", req.Employee, string(hashedPassword))
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(200, gin.H{"message": "User registered successfully"})
}



type RegisterRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Age      int    `json:"age"`
	Employee bool   `json:"employee"`
}
*/
