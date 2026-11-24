package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
)

func itoa(n int) string {
	return strconv.Itoa(n)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{
		"error": message,
	})
}

func decodeJSON(r *http.Request, dst interface{}) error {
	if r.Body == nil {
		return io.EOF
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(dst)
}

func isValidEmail(email string) bool {
	email = strings.TrimSpace(email)
	if email == "" {
		return false
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return false
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	if !strings.Contains(parts[1], ".") {
		return false
	}
	domainParts := strings.Split(parts[1], ".")
	for _, dp := range domainParts {
		if dp == "" {
			return false
		}
	}
	return true
}
