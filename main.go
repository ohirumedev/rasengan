package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type User struct {
	Username       string `bson:"username"`
	HashedPassword string `bson:"hashedpassword"`
	SessionToken   string `bson:"sessiontoken"`
	CSRFToken      string `bson:"csrftoken"`
	Balance        int    `bson:"balance"`
	Admin          bool
}

func setCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "https://crystalogfn.vercel.app" || origin == "https://trigger-diego-attitudes-payments.trycloudflare.com" {

		w.Header().Set("Access-Control-Allow-Origin", "https://crystalogfn.vercel.app")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	}
}

var mongouri = os.Getenv("MONGODB_URI")

var client, err = mongo.Connect(
	context.Background(),
	options.Client().ApplyURI(mongouri),
)

var db = client.Database("vaulty-golang")

var loginInfo = db.Collection("login")

func main() {

	if err != nil {
		fmt.Println("Failled to connect to database. Aborting.")
		return
	}

	router := gin.Default()

	router.POST("/register", register)
	router.POST("/login", login)
	router.POST("/logout", logout)
	router.GET("/protected", protected)
	router.POST("/admin/manage", ChangeUserBalance)
	router.GET("/me", getMe)

	//router.GET("/vault/all", viewAllVault)

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	router.Run(":" + port)
}

func register(minato *gin.Context) {

	itachi := minato.Writer
	shisui := minato.Request

	setCORS(itachi, shisui)
	username := shisui.FormValue("username")
	password := shisui.FormValue("password")
	hashedpassword, _ := hashPassword(password)

	userInfo := User{
		Username:       username,
		HashedPassword: hashedpassword,
		Balance:        0,
	}
	filter := bson.M{"username": username}

	if len(password) < 8 {

		http.Error(itachi, "Invalid password.", http.StatusNotAcceptable)
		return
	}

	err := loginInfo.FindOne(
		context.Background(),
		filter,
	).Decode(&userInfo)

	if err == nil {
		http.Error(itachi, "User already exists", http.StatusConflict)
		return
	}

	_, err = loginInfo.InsertOne(
		context.Background(),
		userInfo,
	)

	if err != nil {
		return
	}

}

func login(minato *gin.Context) {
	itachi := minato.Writer
	shisui := minato.Request

	setCORS(itachi, shisui)
	username := shisui.FormValue("username")
	password := shisui.FormValue("password")
	hashedpassword, err := hashPassword(password)
	if err != nil {
		fmt.Println("Error hashing password.")
		http.Error(itachi, "Error hashing your password", http.StatusFailedDependency)
		return
	}

	userlogin := User{
		Username:       username,
		HashedPassword: hashedpassword,
	}

	filter := bson.M{"username": username}

	err = loginInfo.FindOne(
		context.Background(),
		filter,
	).Decode(&userlogin)

	if err == mongo.ErrNoDocuments {
		http.Error(itachi, "User not found.", http.StatusNotFound)
		return
	}

	if !checkPasswordHash(password, userlogin.HashedPassword) {
		http.Error(itachi, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	sessionToken := generateToken(32)
	csrfToken := generateToken(32)

	http.SetCookie(itachi, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true, // shouldnt be accessible client-side
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})

	http.SetCookie(itachi, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: false, // needs to be accessible client-side
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})

	userlogin.CSRFToken = csrfToken
	userlogin.SessionToken = sessionToken

	update := bson.M{
		"$set": bson.M{"sessiontoken": sessionToken, "csrftoken": csrfToken},
	}

	_, err = loginInfo.UpdateOne(
		context.Background(),
		filter,
		update,
	)
	if err != nil {
		return
	}

	minato.IndentedJSON(200, gin.H{
		"status":   http.StatusOK,
		"username": userlogin.Username,
		"admin":    userlogin.Admin,
		"balance":  userlogin.Balance,
	})

}

func protected(minato *gin.Context) {
	itachi := minato.Writer
	shisui := minato.Request

	var user User

	setCORS(itachi, shisui)
	st, err := shisui.Cookie("session_token")

	if err := AuthorizeViaSession(shisui); err != nil {
		http.Error(itachi, "Authorization failed", http.StatusUnauthorized)
		return
	}

	err = loginInfo.FindOne(
		context.Background(),
		bson.M{"sessiontoken": st.Value},
	).Decode(&user)

	if err == mongo.ErrNoDocuments {
		http.Error(itachi, "User not found.", http.StatusNotFound)
		return
	}

	fmt.Fprintln(itachi, "Welcome!", http.StatusOK)
}

func logout(minato *gin.Context) {
	itachi := minato.Writer
	shisui := minato.Request
	setCORS(itachi, shisui)

	if err := AuthorizeViaSession(shisui); err != nil {
		http.Error(itachi, "Unauthorized", http.StatusUnauthorized)
		return
	}

	http.SetCookie(itachi, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: false,
	})

	http.SetCookie(itachi, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
	})
	username := shisui.FormValue("username")
	var user User
	error := loginInfo.FindOne(
		context.Background(),
		bson.M{"username": username},
	).Decode(&user)

	if error == mongo.ErrNoDocuments {
		http.Error(itachi, "Not found.", http.StatusNotFound)
		return
	}

	fmt.Fprintln(itachi, "Logged out.", http.StatusOK)
}

func ChangeUserBalance(minato *gin.Context) {

	itachi := minato.Writer
	shisui := minato.Request
	setCORS(itachi, shisui)
	username := shisui.FormValue("username")
	change := shisui.FormValue("change")

	changeInt, err := strconv.Atoi(change)
	if err != nil {
		http.Error(itachi, "Failed to parse change", http.StatusFailedDependency)
		return
	}
	var user User

	err = loginInfo.FindOne(
		context.Background(),
		bson.M{"username": username},
	).Decode(&user)

	if err == mongo.ErrNoDocuments {
		http.Error(itachi, "User not found.", http.StatusNotFound)
		return
	}

	var balance int

	if changeInt > 0 {
		balance = user.Balance + changeInt
	} else if changeInt < 0 {
		balance = user.Balance + changeInt
	}

	if err := Authorize(shisui); err != nil {
		http.Error(itachi, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if user.Admin == false {
		http.Error(itachi, "You are not a admin, stop larping sonion.", http.StatusUnauthorized)
		return
	}

	_, err = loginInfo.UpdateOne(
		context.Background(),
		bson.M{"username": username},
		bson.M{
			"$set": bson.M{"balance": balance},
		},
	)

	if err != nil {
		http.Error(itachi, "Could not update the balance of the selected user.", http.StatusBadRequest)
		return
	}

}

func getMe(minato *gin.Context) {
	itachi := minato.Writer
	shisui := minato.Request
	setCORS(itachi, shisui)

	var user User

	st, err := shisui.Cookie("session_token")

	if err := AuthorizeViaSession(shisui); err != nil {
		http.Error(itachi, "Authorization failed", http.StatusUnauthorized)
		return
	}

	if err != nil {
		http.Error(itachi, "Session not found.", http.StatusNotFound)
		return
	}

	err = loginInfo.FindOne(
		context.Background(),
		bson.M{"sessiontoken": st.Value},
	).Decode(&user)

	if err == mongo.ErrNoDocuments {
		http.Error(itachi, "User not found.", http.StatusNotFound)
		return
	}

	minato.IndentedJSON(200, gin.H{
		"username": user.Username,
		"balance":  user.Balance,
		"admin":    user.Admin,
	})

}
