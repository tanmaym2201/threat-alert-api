package main

import (
	"net/http"
	"sort"
	"strings"
	"time"
)

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrgName string `json:"orgName"`
		Name    string `json:"name"`
		Email   string `json:"email"`
	}

	if decodeJSON(r, &req) != nil {
		writeError(w, 400, "invalid JSON")
		return
	}

	req.OrgName = strings.TrimSpace(req.OrgName)
	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.TrimSpace(req.Email)

	if req.OrgName == "" || req.Name == "" || !isValidEmail(req.Email) {
		writeError(w, 400, "invalid registration details")
		return
	}

	token, err := generateSecret()
	if err != nil {
		writeError(w, 500, "token generation failed")
		return
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	orgID := db.nextOrgID()
	userID := db.nextUserID()

	company := Company{
		OrgID:   orgID,
		OrgName: req.OrgName,
	}

	user := User{
		UserID: userID,
		OrgID:  orgID,
		Name:   req.Name,
		Email:  req.Email,
		Role:   "admin",
		Token:  token,
	}

	db.companies[orgID] = company
	db.users[userID] = user
	db.userTokens[token] = userID

	writeJSON(w, 201, user)
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	user, err := authenticateUser(r)
	if err != nil {
		writeError(w, 401, err.Error())
		return
	}

	if !requireAdmin(w, user) {
		return
	}

	var req struct {
		Name  string `json:"name"`
		Email string `json:"email"`
		Role  string `json:"role"`
	}

	if decodeJSON(r, &req) != nil {
		writeError(w, 400, "invalid JSON")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.TrimSpace(req.Email)
	req.Role = strings.TrimSpace(req.Role)

	if req.Name == "" || !isValidEmail(req.Email) ||
		(req.Role != "admin" && req.Role != "viewer") {
		writeError(w, 400, "invalid user details")
		return
	}

	token, err := generateSecret()
	if err != nil {
		writeError(w, 500, "token generation failed")
		return
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	userID := db.nextUserID()

	newUser := User{
		UserID: userID,
		OrgID:  user.OrgID,
		Name:   req.Name,
		Email:  req.Email,
		Role:   req.Role,
		Token:  token,
	}

	db.users[userID] = newUser
	db.userTokens[token] = userID

	writeJSON(w, 201, newUser)
}

func appsHandler(w http.ResponseWriter, r *http.Request) {
	user, err := authenticateUser(r)
	if err != nil {
		writeError(w, 401, err.Error())
		return
	}

	if !requireAdmin(w, user) {
		return
	}

	var req struct {
		Name     string `json:"name"`
		Platform string `json:"platform"`
	}

	if decodeJSON(r, &req) != nil {
		writeError(w, 400, "invalid JSON")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Platform = strings.TrimSpace(req.Platform)

	if req.Name == "" ||
		(req.Platform != "android" && req.Platform != "ios") {
		writeError(w, 400, "invalid app details")
		return
	}

	key, err := generateSecret()
	if err != nil {
		writeError(w, 500, "key generation failed")
		return
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	appID := db.nextAppID()

	app := App{
		AppID:    appID,
		OrgID:    user.OrgID,
		Name:     req.Name,
		Platform: req.Platform,
		AppKey:   key,
	}

	db.apps[appID] = app
	db.appKeys[key] = appID

	writeJSON(w, 201, app)
}

func createAlertHandler(w http.ResponseWriter, r *http.Request) {
	app, err := authenticateApp(r)
	if err != nil {
		writeError(w, 401, err.Error())
		return
	}

	var req struct {
		DeviceID   string      `json:"deviceId"`
		ThreatType string      `json:"threatType"`
		Severity   interface{} `json:"severity"`
	}

	if decodeJSON(r, &req) != nil {
		writeError(w, 400, "invalid JSON")
		return
	}

	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.ThreatType = strings.TrimSpace(req.ThreatType)

	if req.DeviceID == "" || req.ThreatType == "" || req.Severity == nil {
		writeError(w, 400, "invalid alert details")
		return
	}

	sevFloat, ok := req.Severity.(float64)
	if !ok {
		writeError(w, 400, "invalid severity")
		return
	}
	if sevFloat != float64(int(sevFloat)) {
		writeError(w, 400, "severity must be a whole number")
		return
	}
	severity := int(sevFloat)
	if severity < 1 || severity > 5 {
		writeError(w, 400, "severity must be between 1 and 5")
		return
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC()

	for id, alert := range db.alerts {
		if alert.AppID == app.AppID &&
			alert.DeviceID == req.DeviceID &&
			alert.ThreatType == req.ThreatType &&
			alert.Status == "open" {

			alert.Count++
			alert.LastSeen = now
			db.alerts[id] = alert

			writeJSON(w, 200, alert)
			return
		}
	}

	alert := Alert{
		ID:         db.nextAlertID(),
		OrgID:      app.OrgID,
		AppID:      app.AppID,
		DeviceID:   req.DeviceID,
		ThreatType: req.ThreatType,
		Severity:   severity,
		Count:      1,
		Status:     "open",
		FirstSeen:  now,
		LastSeen:   now,
		ResolvedBy: "",
	}

	db.alerts[alert.ID] = alert

	writeJSON(w, 201, alert)
}

func listAlertsHandler(w http.ResponseWriter, r *http.Request) {
	user, err := authenticateUser(r)
	if err != nil {
		writeError(w, 401, err.Error())
		return
	}

	status := r.URL.Query().Get("status")

	if status != "" && status != "open" && status != "resolved" {
		writeError(w, 400, "invalid status")
		return
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	alerts := make([]Alert, 0)

	for _, alert := range db.alerts {
		if alert.OrgID != user.OrgID {
			continue
		}

		if status != "" && alert.Status != status {
			continue
		}

		alerts = append(alerts, alert)
	}

	sort.Slice(alerts, func(i, j int) bool {
		if alerts[i].LastSeen.Equal(alerts[j].LastSeen) {
			return alerts[i].ID > alerts[j].ID
		}
		return alerts[i].LastSeen.After(alerts[j].LastSeen)
	})

	writeJSON(w, 200, map[string]interface{}{
		"alerts": alerts,
	})
}

func getAlertHandler(w http.ResponseWriter, r *http.Request) {
	user, err := authenticateUser(r)
	if err != nil {
		writeError(w, 401, err.Error())
		return
	}

	id := r.PathValue("id")

	db.mu.Lock()
	defer db.mu.Unlock()

	alert, exists := db.alerts[id]

	if !exists || alert.OrgID != user.OrgID {
		writeError(w, 404, "alert not found")
		return
	}

	writeJSON(w, 200, alert)
}

func resolveAlertHandler(w http.ResponseWriter, r *http.Request) {
	user, err := authenticateUser(r)
	if err != nil {
		writeError(w, 401, err.Error())
		return
	}

	if !requireAdmin(w, user) {
		return
	}

	id := r.PathValue("id")

	db.mu.Lock()
	defer db.mu.Unlock()

	alert, exists := db.alerts[id]

	if !exists || alert.OrgID != user.OrgID {
		writeError(w, 404, "alert not found")
		return
	}

	if alert.Status == "resolved" {
		writeError(w, 409, "alert already resolved")
		return
	}

	alert.Status = "resolved"
	alert.ResolvedBy = user.UserID

	db.alerts[id] = alert

	writeJSON(w, 200, alert)
}
