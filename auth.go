package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
)

func generateSecret() (string, error) {
	bytes := make([]byte, 32)

	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

func authenticateUser(r *http.Request) (User, error) {
	header := r.Header.Get("Authorization")

	if !strings.HasPrefix(header, "Bearer ") {
		return User{}, errors.New("missing or invalid token")
	}

	token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))

	if token == "" {
		return User{}, errors.New("missing or invalid token")
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	userID, exists := db.userTokens[token]
	if !exists {
		return User{}, errors.New("invalid token")
	}

	user, exists := db.users[userID]
	if !exists {
		return User{}, errors.New("invalid token")
	}

	return user, nil
}

func authenticateApp(r *http.Request) (App, error) {
	key := r.Header.Get("X-App-Key")

	if key == "" {
		return App{}, errors.New("missing app key")
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	appID, exists := db.appKeys[key]
	if !exists {
		return App{}, errors.New("invalid app key")
	}

	app, exists := db.apps[appID]
	if !exists {
		return App{}, errors.New("invalid app key")
	}

	return app, nil
}

func requireAdmin(w http.ResponseWriter, user User) bool {
	if user.Role != "admin" {
		writeError(w, http.StatusForbidden, "only an admin can do this")
		return false
	}

	return true
}
