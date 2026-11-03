package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
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
}

type Location struct {
	Name    string `bson:"name"`
	Address string `bson:"address"`
	Likes   int    `bson:"likes"`
	Poster  string `bson:"poster"`
	ID      int    `bson:"id"`
	Image   string `bson:"image"`
}

type SavedSlots struct {
	Owner string   `bson:"owner"` // all of deez save locationIDs i dont wanna do allat
	Slot1 Location `bson:"slot1"`
	Slot2 Location `bson:"slot2"`
	Slot3 Location `bson:"slot3"`
	Slot4 Location `bson:"slot4"`
	Slot5 Location `bson:"slot5"`
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
	options.Client().ApplyURI("mongodb://localhost:27017"),
)

var db = client.Database("vaulty-golang")

var loginInfo = db.Collection("login")

var location = db.Collection("location")
var slots = db.Collection("slots")

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
	router.GET("/me", getMe)
	router.POST("/location/create", createLocation)
	router.POST("/location/search", SearchLocation)

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

	userSlots := SavedSlots{
		Owner: username,
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
		http.Error(itachi, "User registration failed.", http.StatusFailedDependency)
		return
	}

	_, err = slots.InsertOne(
		context.Background(),
		userSlots,
	)

	if err != nil {
		http.Error(itachi, "Creation of location slots  failed.", http.StatusFailedDependency)
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

		"balance": userlogin.Balance,
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
	st, err := shisui.Cookie("session_token")
	if err != nil {
		http.Error(itachi, "Could not get session.", http.StatusNotFound)
		return
	}

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

	var user User
	error := loginInfo.FindOne(
		context.Background(),
		bson.M{"sessiontoken": st.Value},
	).Decode(&user)

	if error == mongo.ErrNoDocuments {
		http.Error(itachi, "Not found.", http.StatusNotFound)
		return
	}

	fmt.Fprintln(itachi, "Logged out.", http.StatusOK)
}

func createLocation(minato *gin.Context) {
	itachi := minato.Writer
	shisui := minato.Request
	setCORS(itachi, shisui)
	name := shisui.FormValue("name")
	address := shisui.FormValue("address")
	image := shisui.FormValue("image")

	locationID := generateToken(8)
	var Userinfo User
	var Location Location
	st, err := shisui.Cookie("session_token")

	if err != nil {
		http.Error(itachi, "Could not find session.", http.StatusUnauthorized)
		return
	}

	err = loginInfo.FindOne(
		context.Background(),
		bson.M{"sessiontoken": st.Value},
	).Decode(&Userinfo)

	if err == mongo.ErrNoDocuments {
		http.Error(itachi, "Cannot find user.", http.StatusNotFound)
		return
	}

	if err := AuthorizeViaSession(shisui); err != nil {
		http.Error(itachi, "Unauthorized", http.StatusUnauthorized)
		return
	}

	formattedName := strings.ToLower(name)

	err = location.FindOne(
		context.Background(),
		bson.M{"name": formattedName},
	).Decode(&Location)

	if err != mongo.ErrNoDocuments {
		http.Error(itachi, "Location already exists.", http.StatusConflict)
		return
	}
	_, err = location.InsertOne(
		context.Background(),
		bson.M{"name": formattedName, "address": address, "poster": Userinfo.Username},
	)

	if err != nil {
		http.Error(itachi, "Failed to upload location", http.StatusInternalServerError)
		return
	}

	minato.IndentedJSON(200, gin.H{
		"name":     name,
		"address":  address,
		"likes":    "0",
		"poster":   Userinfo.Username,
		"id":       locationID,
		"imageURL": image,
	})

}

func getMe(minato *gin.Context) {
	itachi := minato.Writer
	shisui := minato.Request
	setCORS(itachi, shisui)
	var Userinfo User
	var savedSlots SavedSlots

	st, err := shisui.Cookie("session_token")

	if err != nil {
		http.Error(itachi, "Could not find session.", http.StatusNotFound)
		return
	}

	if err := AuthorizeViaSession(shisui); err != nil {
		http.Error(itachi, "Unauthorized", http.StatusUnauthorized)
		return
	}

	err = loginInfo.FindOne(
		context.Background(),
		bson.M{"sessiontoken": st.Value},
	).Decode(&Userinfo)

	if err == mongo.ErrNoDocuments {
		http.Error(itachi, "Could not find your login.", http.StatusNotFound)
		return
	}

	err = slots.FindOne(
		context.Background(),
		bson.M{"owner": Userinfo.Username},
	).Decode(&savedSlots)

	minato.IndentedJSON(200,
		gin.H{
			"username": Userinfo.Username,
			"saved1":   savedSlots.Slot1,
			"saved2":   savedSlots.Slot2,
			"saved3":   savedSlots.Slot3,
			"saved4":   savedSlots.Slot4,
			"saved5":   savedSlots.Slot5,
		})

}

func SearchLocation(minato *gin.Context) {
	itachi := minato.Writer
	shisui := minato.Request
	query := shisui.FormValue("query")
	targetSlot := shisui.FormValue("targetslot")
	save := shisui.FormValue("save")

	setCORS(itachi, shisui)
	var Userinfo User
	var savedSlots SavedSlots

	st, err := shisui.Cookie("session_token")

	if err != nil {
		http.Error(itachi, "Could not find session.", http.StatusNotFound)
		return
	}

	if err := AuthorizeViaSession(shisui); err != nil {
		http.Error(itachi, "Unauthorized", http.StatusUnauthorized)
		return
	}

	err = loginInfo.FindOne(
		context.Background(),
		bson.M{"sessiontoken": st.Value},
	).Decode(&Userinfo)

	if err == mongo.ErrNoDocuments {
		http.Error(itachi, "Could not find user.", http.StatusNotFound)
		return
	}

	err = slots.FindOne(
		context.Background(),
		bson.M{"owner": Userinfo.Username},
	).Decode(&savedSlots)

	if err == mongo.ErrNoDocuments {
		http.Error(itachi, "Could not find the user's slots.", http.StatusNotFound)
		return
	}

	formattedQuery := strings.ToLower(query)
	var finishedQuery Location
	err = location.FindOne(
		context.Background(),
		bson.M{"name": formattedQuery},
	).Decode(&finishedQuery)

	if err == mongo.ErrNoDocuments {
		http.Error(itachi, "Did not find any documents that matched the query", http.StatusNotFound)
		return
	}

	if save == "yes" {
		i, err := strconv.Atoi(targetSlot)
		if err != nil {
			http.Error(itachi, "Could not parse slot.", http.StatusInternalServerError)
			return
		}
		if i == 1 {
			_, err = slots.UpdateOne(
				context.Background(),
				bson.M{"owner": Userinfo.Username},
				bson.M{
					"$set": bson.M{"slot1": finishedQuery},
				},
			)
		}

		if i == 2 {
			_, err = slots.UpdateOne(
				context.Background(),
				bson.M{"owner": Userinfo.Username},
				bson.M{
					"$set": bson.M{"slot2": finishedQuery},
				},
			)
		}

		if i == 3 {
			_, err = slots.UpdateOne(
				context.Background(),
				bson.M{"owner": Userinfo.Username},
				bson.M{
					"$set": bson.M{"slot3": finishedQuery},
				},
			)
		}

		if i == 4 {
			_, err = slots.UpdateOne(
				context.Background(),
				bson.M{"owner": Userinfo.Username},
				bson.M{
					"$set": bson.M{"slot4": finishedQuery},
				},
			)
		}

		if i == 5 {
			_, err = slots.UpdateOne(
				context.Background(),
				bson.M{"owner": Userinfo.Username},
				bson.M{
					"$set": bson.M{"slot5": finishedQuery},
				},
			)
		}

		if i > 5 {
			http.Error(itachi, "Please select a slot number equal to or lower than 5.", http.StatusBadRequest)
			return
		}

		minato.IndentedJSON(200,
			gin.H{
				"name":    finishedQuery.Name,
				"likes":   finishedQuery.Likes,
				"poster":  finishedQuery.Poster,
				"address": finishedQuery.Address,
				"image":   finishedQuery.Image,
			})
		return
	}
	if save == "no" {
		minato.IndentedJSON(200,
			gin.H{
				"name":    finishedQuery.Name,
				"likes":   finishedQuery.Likes,
				"poster":  finishedQuery.Poster,
				"address": finishedQuery.Address,
				"image":   finishedQuery.Image,
			})
		return
	}
	if save != "no" && save != "yes" {
		http.Error(itachi, "Invalid option. Only yes or no are supported", http.StatusBadRequest)
		return
	}
}

func GetSlot(minato *gin.Context) {
	itachi := minato.Writer
	shisui := minato.Request
	slotNumber := shisui.FormValue("slotnumber")
	setCORS(itachi, shisui)

	var savedSlots SavedSlots

	slotInt, err := strconv.Atoi(slotNumber)
	if err != nil {
		http.Error(itachi, "Failed to parse location slot number.", http.StatusFailedDependency)
		return
	}

	st, err := shisui.Cookie("session_token")

	if err != nil {
		http.Error(itachi, "Could not find session.", http.StatusNotFound)
		return
	}

	if err := AuthorizeViaSession(shisui); err != nil {
		http.Error(itachi, "Unauthorized", http.StatusUnauthorized)
		return
	}

	err = slots.FindOne(
		context.Background(),
		bson.M{"sessiontoken": st.Value},
	).Decode(&savedSlots)

	if err == mongo.ErrNoDocuments {
		http.Error(itachi, "Could not find user's location slots.", http.StatusNotFound)
		return
	}

	if slotInt == 1 {
		minato.IndentedJSON(200,
			gin.H{
				"address": savedSlots.Slot1.Address,
				"poster":  savedSlots.Slot1.Poster,
				"name":    savedSlots.Slot1.Name,
				"likes":   savedSlots.Slot1.Likes,
				"image":   savedSlots.Slot1.Image,
			})
	}

	if slotInt == 2 {
		minato.IndentedJSON(200,
			gin.H{
				"address": savedSlots.Slot2.Address,
				"poster":  savedSlots.Slot2.Poster,
				"name":    savedSlots.Slot2.Name,
				"likes":   savedSlots.Slot2.Likes,
				"image":   savedSlots.Slot2.Image,
			})
	}

	if slotInt == 3 {
		minato.IndentedJSON(200,
			gin.H{
				"address": savedSlots.Slot3.Address,
				"poster":  savedSlots.Slot3.Poster,
				"name":    savedSlots.Slot3.Name,
				"likes":   savedSlots.Slot3.Likes,
				"image":   savedSlots.Slot3.Image,
			})
	}

	if slotInt == 4 {
		minato.IndentedJSON(200,
			gin.H{
				"address": savedSlots.Slot4.Address,
				"poster":  savedSlots.Slot4.Poster,
				"name":    savedSlots.Slot4.Name,
				"likes":   savedSlots.Slot4.Likes,
				"image":   savedSlots.Slot4.Image,
			})
	}

	if slotInt == 5 {
		minato.IndentedJSON(200,
			gin.H{
				"address": savedSlots.Slot5.Address,
				"poster":  savedSlots.Slot5.Poster,
				"name":    savedSlots.Slot5.Name,
				"likes":   savedSlots.Slot5.Likes,
				"image":   savedSlots.Slot5.Image,
			})
	}

	if slotInt > 5 || slotInt < 1 {
		http.Error(itachi, "Slot number numbers higher than 5 and lower than 1 are not accepted.", http.StatusBadRequest)
		return
	}

}
