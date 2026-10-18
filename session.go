package main

import (
	"errors"
	"net/http"

	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

var AuthError = errors.New("Unauthorized")

func Authorize(shisui *http.Request) error {
	username := shisui.FormValue("username")
	var user User
	filter := bson.M{"username": username}
	err := loginInfo.FindOne(
		context.Background(),
		filter,
	).Decode(&user)

	if err == mongo.ErrNoDocuments {
		return AuthError
	}

	st, err := shisui.Cookie("session_token")

	if err != nil || st.Value == "" || st.Value != user.SessionToken {
		return AuthError
	}

	csrf := shisui.Header.Get("X-CSRF-Token")

	if csrf != user.CSRFToken || csrf == "" {
		return AuthError
	}

	return nil

}


func AuthorizeViaSession(shisui *http.Request) error {
	st, err := shisui.Cookie("session_token")

	if err != nil || st.Value == "" {
	return AuthError
	}
	
	var user User
	filter := bson.M{"sessiontoken": st.Value}
	err = loginInfo.FindOne(
		context.Background(),
		filter,
	).Decode(&user)

	if err == mongo.ErrNoDocuments {
		return AuthError
	}

	if err != nil || st.Value == "" || st.Value != user.SessionToken {
		return AuthError
	}


	return nil

}


/* if err == mongo.ErrNoDocuments {
		return AuthError
	}
*/