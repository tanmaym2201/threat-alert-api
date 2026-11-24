package main

import (
	"log"
	"net/http"
	"os"
)

func setupRouter() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /register", registerHandler)
	mux.HandleFunc("POST /users", usersHandler)
	mux.HandleFunc("POST /apps", appsHandler)
	mux.HandleFunc("POST /alerts", createAlertHandler)
	mux.HandleFunc("GET /alerts", listAlertsHandler)
	mux.HandleFunc("GET /alerts/{id}", getAlertHandler)
	mux.HandleFunc("POST /alerts/{id}/resolve", resolveAlertHandler)

	return mux
}

func main() {
	mux := setupRouter()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Println("Threat Alert API running on port " + port)

	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}
