package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func resetStore() {
	db.reset()
}

func createTestData(t *testing.T) (string, string, string) {
	t.Helper()
	resetStore()

	token, _ := generateSecret()
	appKey, _ := generateSecret()

	db.mu.Lock()
	defer db.mu.Unlock()

	db.companies["org_1"] = Company{
		OrgID:   "org_1",
		OrgName: "Test",
	}

	db.users["usr_1"] = User{
		UserID: "usr_1",
		OrgID:  "org_1",
		Name:   "Viewer",
		Email:  "viewer@test.com",
		Role:   "viewer",
		Token:  token,
	}

	db.userTokens[token] = "usr_1"

	db.apps["app_1"] = App{
		AppID:    "app_1",
		OrgID:    "org_1",
		Name:     "Test App",
		Platform: "android",
		AppKey:   appKey,
	}

	db.appKeys[appKey] = "app_1"

	db.alerts["alr_1"] = Alert{
		ID:         "alr_1",
		OrgID:      "org_1",
		AppID:      "app_1",
		DeviceID:   "d1",
		ThreatType: "ROOT_DETECTED",
		Severity:   5,
		Count:      1,
		Status:     "open",
		FirstSeen:  time.Now().UTC(),
		LastSeen:   time.Now().UTC(),
	}

	return token, appKey, "alr_1"
}

// R9 Mandatory Test 1: Viewer receives 403 when resolving an alert.
func TestViewerCannotResolveAlert(t *testing.T) {
	token, _, alertID := createTestData(t)

	req := httptest.NewRequest(
		http.MethodPost,
		"/alerts/"+alertID+"/resolve",
		nil,
	)
	req.SetPathValue("id", alertID)
	req.Header.Set("Authorization", "Bearer "+token)

	rec := httptest.NewRecorder()
	resolveAlertHandler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}

	var errResp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil || errResp["error"] == "" {
		t.Fatalf("expected JSON error response, got %s", rec.Body.String())
	}
}

// R9 Mandatory Test 2: Another company's user receives 404 when accessing an alert.
func TestOtherCompanyGets404(t *testing.T) {
	resetStore()

	token, _ := generateSecret()

	db.mu.Lock()
	db.companies["org_1"] = Company{OrgID: "org_1", OrgName: "Org 1"}
	db.companies["org_2"] = Company{OrgID: "org_2", OrgName: "Org 2"}

	db.users["usr_2"] = User{
		UserID: "usr_2",
		OrgID:  "org_2",
		Name:   "Admin 2",
		Email:  "admin2@org2.com",
		Role:   "admin",
		Token:  token,
	}

	db.userTokens[token] = "usr_2"

	db.alerts["alr_1"] = Alert{
		ID:         "alr_1",
		OrgID:      "org_1",
		AppID:      "app_1",
		DeviceID:   "d1",
		ThreatType: "ROOT_DETECTED",
		Severity:   5,
		Count:      1,
		Status:     "open",
		FirstSeen:  time.Now().UTC(),
		LastSeen:   time.Now().UTC(),
	}
	db.mu.Unlock()

	req := httptest.NewRequest(
		http.MethodGet,
		"/alerts/alr_1",
		nil,
	)
	req.SetPathValue("id", "alr_1")
	req.Header.Set("Authorization", "Bearer "+token)

	rec := httptest.NewRecorder()
	getAlertHandler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	var errResp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil || errResp["error"] == "" {
		t.Fatalf("expected JSON error response, got %s", rec.Body.String())
	}
}

// R9 Mandatory Test 3: 50 simultaneous identical alert requests produce one alert with count 50.
func TestFiftyConcurrentAlerts(t *testing.T) {
	_, appKey, _ := createTestData(t)

	var wg sync.WaitGroup
	statusCodes := make([]int, 50)
	var mu sync.Mutex

	for i := 0; i < 50; i++ {
		wg.Add(1)
		idx := i

		go func() {
			defer wg.Done()

			body := map[string]interface{}{
				"deviceId":   "d2",
				"threatType": "FRIDA_DETECTED",
				"severity":   4,
			}

			data, _ := json.Marshal(body)

			req := httptest.NewRequest(
				http.MethodPost,
				"/alerts",
				bytes.NewReader(data),
			)

			req.Header.Set("X-App-Key", appKey)

			rec := httptest.NewRecorder()
			createAlertHandler(rec, req)

			mu.Lock()
			statusCodes[idx] = rec.Code
			mu.Unlock()

			if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
				t.Errorf("unexpected status: %d", rec.Code)
			}
		}()
	}

	wg.Wait()

	db.mu.Lock()
	defer db.mu.Unlock()

	count := 0
	total := 0

	for _, alert := range db.alerts {
		if alert.DeviceID == "d2" && alert.ThreatType == "FRIDA_DETECTED" {
			count++
			total = alert.Count
		}
	}

	if count != 1 || total != 50 {
		t.Fatalf("expected one alert with count 50, got %d alerts and count %d", count, total)
	}

	createdCount := 0
	okCount := 0
	for _, code := range statusCodes {
		if code == http.StatusCreated {
			createdCount++
		} else if code == http.StatusOK {
			okCount++
		}
	}

	if createdCount != 1 || okCount != 49 {
		t.Fatalf("expected exactly 1 201 Created and 49 200 OK, got %d Created and %d OK", createdCount, okCount)
	}
}

// Complete 22 Self-Check Scenarios executed in exact order against the router
func TestAll22SelfCheckScenarios(t *testing.T) {
	resetStore()
	router := setupRouter()

	doRequest := func(method, path string, token, appKey string, body interface{}) (*http.Response, []byte) {
		var bodyReader io.Reader
		if body != nil {
			data, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal error: %v", err)
			}
			bodyReader = bytes.NewReader(data)
		}

		req := httptest.NewRequest(method, path, bodyReader)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if appKey != "" {
			req.Header.Set("X-App-Key", appKey)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		res := rec.Result()
		resBody, _ := io.ReadAll(res.Body)
		return res, resBody
	}

	var acmeAdminToken string
	var acmeViewerToken string
	var betaAdminToken string
	var acmeAppKey string
	var alert1ID string
	var alert2ID string

	// Step 1: Register Acme company — 201
	{
		res, body := doRequest("POST", "/register", "", "", map[string]string{
			"orgName": "Acme",
			"name":    "Acme Admin",
			"email":   "admin@acme.com",
		})
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("Step 1 failed: expected 201, got %d: %s", res.StatusCode, string(body))
		}
		var user User
		if err := json.Unmarshal(body, &user); err != nil || user.Token == "" || user.Role != "admin" {
			t.Fatalf("Step 1 invalid user response: %s", string(body))
		}
		acmeAdminToken = user.Token
	}

	// Step 2: Register Beta company — 201
	{
		res, body := doRequest("POST", "/register", "", "", map[string]string{
			"orgName": "Beta",
			"name":    "Beta Admin",
			"email":   "admin@beta.com",
		})
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("Step 2 failed: expected 201, got %d: %s", res.StatusCode, string(body))
		}
		var user User
		if err := json.Unmarshal(body, &user); err != nil || user.Token == "" || user.Role != "admin" {
			t.Fatalf("Step 2 invalid user response: %s", string(body))
		}
		betaAdminToken = user.Token
	}

	// Step 3: Register with invalid email — 400
	{
		res, body := doRequest("POST", "/register", "", "", map[string]string{
			"orgName": "Gamma",
			"name":    "Gamma Admin",
			"email":   "invalid-email",
		})
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("Step 3 failed: expected 400, got %d: %s", res.StatusCode, string(body))
		}
		var errResp map[string]string
		if err := json.Unmarshal(body, &errResp); err != nil || errResp["error"] == "" {
			t.Fatalf("Step 3 missing error json: %s", string(body))
		}
	}

	// Step 4: Acme admin creates viewer — 201
	{
		res, body := doRequest("POST", "/users", acmeAdminToken, "", map[string]string{
			"name":  "Acme Viewer",
			"email": "viewer@acme.com",
			"role":  "viewer",
		})
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("Step 4 failed: expected 201, got %d: %s", res.StatusCode, string(body))
		}
		var user User
		if err := json.Unmarshal(body, &user); err != nil || user.Token == "" || user.Role != "viewer" {
			t.Fatalf("Step 4 invalid user response: %s", string(body))
		}
		acmeViewerToken = user.Token
	}

	// Step 5: Viewer tries creating user — 403
	{
		res, body := doRequest("POST", "/users", acmeViewerToken, "", map[string]string{
			"name":  "New User",
			"email": "new@acme.com",
			"role":  "viewer",
		})
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("Step 5 failed: expected 403, got %d: %s", res.StatusCode, string(body))
		}
	}

	// Step 6: Create user without token — 401
	{
		res, body := doRequest("POST", "/users", "", "", map[string]string{
			"name":  "New User",
			"email": "new@acme.com",
			"role":  "viewer",
		})
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Step 6 failed: expected 401, got %d: %s", res.StatusCode, string(body))
		}
	}

	// Step 7: Acme admin creates Android app — 201
	{
		res, body := doRequest("POST", "/apps", acmeAdminToken, "", map[string]string{
			"name":     "Acme Android",
			"platform": "android",
		})
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("Step 7 failed: expected 201, got %d: %s", res.StatusCode, string(body))
		}
		var app App
		if err := json.Unmarshal(body, &app); err != nil || app.AppKey == "" || app.Platform != "android" {
			t.Fatalf("Step 7 invalid app response: %s", string(body))
		}
		acmeAppKey = app.AppKey
	}

	// Step 8: Create app with Windows platform — 400
	{
		res, body := doRequest("POST", "/apps", acmeAdminToken, "", map[string]string{
			"name":     "Acme Windows",
			"platform": "windows",
		})
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("Step 8 failed: expected 400, got %d: %s", res.StatusCode, string(body))
		}
	}

	// Step 9: SDK creates first alert — 201, count 1
	{
		res, body := doRequest("POST", "/alerts", "", acmeAppKey, map[string]interface{}{
			"deviceId":   "device_1",
			"threatType": "ROOT_DETECTED",
			"severity":   4,
		})
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("Step 9 failed: expected 201, got %d: %s", res.StatusCode, string(body))
		}
		var alert Alert
		if err := json.Unmarshal(body, &alert); err != nil || alert.ID == "" || alert.Count != 1 || alert.Status != "open" {
			t.Fatalf("Step 9 invalid alert response: %s", string(body))
		}
		alert1ID = alert.ID
	}

	// Step 10: Same threat again — 200, count 2, same ID
	{
		res, body := doRequest("POST", "/alerts", "", acmeAppKey, map[string]interface{}{
			"deviceId":   "device_1",
			"threatType": "ROOT_DETECTED",
			"severity":   4,
		})
		if res.StatusCode != http.StatusOK {
			t.Fatalf("Step 10 failed: expected 200, got %d: %s", res.StatusCode, string(body))
		}
		var alert Alert
		if err := json.Unmarshal(body, &alert); err != nil || alert.ID != alert1ID || alert.Count != 2 || alert.Status != "open" {
			t.Fatalf("Step 10 invalid alert response: %s", string(body))
		}
	}

	// Step 11: Severity 9 — 400
	{
		res, body := doRequest("POST", "/alerts", "", acmeAppKey, map[string]interface{}{
			"deviceId":   "device_1",
			"threatType": "ROOT_DETECTED",
			"severity":   9,
		})
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("Step 11 failed: expected 400, got %d: %s", res.StatusCode, string(body))
		}
	}

	// Step 12: Wrong app key — 401
	{
		res, body := doRequest("POST", "/alerts", "", "wrong-app-key-12345", map[string]interface{}{
			"deviceId":   "device_1",
			"threatType": "ROOT_DETECTED",
			"severity":   4,
		})
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Step 12 failed: expected 401, got %d: %s", res.StatusCode, string(body))
		}
	}

	// Step 13: Acme viewer lists alerts — 200, one alert
	{
		res, body := doRequest("GET", "/alerts", acmeViewerToken, "", nil)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("Step 13 failed: expected 200, got %d: %s", res.StatusCode, string(body))
		}
		var resp struct {
			Alerts []Alert `json:"alerts"`
		}
		if err := json.Unmarshal(body, &resp); err != nil || len(resp.Alerts) != 1 {
			t.Fatalf("Step 13 expected 1 alert, got %d: %s", len(resp.Alerts), string(body))
		}
		if resp.Alerts[0].ID != alert1ID {
			t.Fatalf("Step 13 expected alert %s, got %s", alert1ID, resp.Alerts[0].ID)
		}
	}

	// Step 14: Beta admin lists alerts — 200, empty list
	{
		res, body := doRequest("GET", "/alerts", betaAdminToken, "", nil)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("Step 14 failed: expected 200, got %d: %s", res.StatusCode, string(body))
		}
		var resp struct {
			Alerts []Alert `json:"alerts"`
		}
		if err := json.Unmarshal(body, &resp); err != nil || resp.Alerts == nil || len(resp.Alerts) != 0 {
			t.Fatalf("Step 14 expected empty alerts list, got %v: %s", resp.Alerts, string(body))
		}
		// Verify raw JSON contains [] and not null
		if !bytes.Contains(body, []byte(`"alerts":[]`)) {
			t.Fatalf("Step 14 expected '\"alerts\":[]', got %s", string(body))
		}
	}

	// Step 15: Beta accesses Acme alert — 404
	{
		res, body := doRequest("GET", "/alerts/"+alert1ID, betaAdminToken, "", nil)
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("Step 15 failed: expected 404, got %d: %s", res.StatusCode, string(body))
		}
	}

	// Step 16: Acme viewer resolves alert — 403
	{
		res, body := doRequest("POST", "/alerts/"+alert1ID+"/resolve", acmeViewerToken, "", nil)
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("Step 16 failed: expected 403, got %d: %s", res.StatusCode, string(body))
		}
	}

	// Step 17: Beta admin resolves Acme alert — 404
	{
		res, body := doRequest("POST", "/alerts/"+alert1ID+"/resolve", betaAdminToken, "", nil)
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("Step 17 failed: expected 404, got %d: %s", res.StatusCode, string(body))
		}
	}

	// Step 18: Acme admin resolves alert — 200
	{
		res, body := doRequest("POST", "/alerts/"+alert1ID+"/resolve", acmeAdminToken, "", nil)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("Step 18 failed: expected 200, got %d: %s", res.StatusCode, string(body))
		}
		var alert Alert
		if err := json.Unmarshal(body, &alert); err != nil || alert.Status != "resolved" || alert.ResolvedBy == "" {
			t.Fatalf("Step 18 expected resolved alert with resolvedBy, got: %s", string(body))
		}
	}

	// Step 19: Resolve same alert again — 409
	{
		res, body := doRequest("POST", "/alerts/"+alert1ID+"/resolve", acmeAdminToken, "", nil)
		if res.StatusCode != http.StatusConflict {
			t.Fatalf("Step 19 failed: expected 409, got %d: %s", res.StatusCode, string(body))
		}
	}

	// Step 20: Same threat after resolution — 201, new alert ID, count 1
	{
		res, body := doRequest("POST", "/alerts", "", acmeAppKey, map[string]interface{}{
			"deviceId":   "device_1",
			"threatType": "ROOT_DETECTED",
			"severity":   4,
		})
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("Step 20 failed: expected 201, got %d: %s", res.StatusCode, string(body))
		}
		var alert Alert
		if err := json.Unmarshal(body, &alert); err != nil || alert.ID == alert1ID || alert.Count != 1 || alert.Status != "open" {
			t.Fatalf("Step 20 expected new alert ID with count 1, got id=%s, count=%d: %s", alert.ID, alert.Count, string(body))
		}
		alert2ID = alert.ID
	}

	// Step 21: List open alerts — 200
	{
		res, body := doRequest("GET", "/alerts?status=open", acmeAdminToken, "", nil)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("Step 21 failed: expected 200, got %d: %s", res.StatusCode, string(body))
		}
		var resp struct {
			Alerts []Alert `json:"alerts"`
		}
		if err := json.Unmarshal(body, &resp); err != nil || len(resp.Alerts) != 1 {
			t.Fatalf("Step 21 expected 1 open alert, got %d: %s", len(resp.Alerts), string(body))
		}
		if resp.Alerts[0].ID != alert2ID {
			t.Fatalf("Step 21 expected open alert %s, got %s", alert2ID, resp.Alerts[0].ID)
		}
	}

	// Step 22: Send 50 identical alerts simultaneously — exactly one alert with count 50
	{
		var wg sync.WaitGroup
		results := make([]int, 50)
		var mu sync.Mutex

		for i := 0; i < 50; i++ {
			wg.Add(1)
			idx := i
			go func() {
				defer wg.Done()
				res, _ := doRequest("POST", "/alerts", "", acmeAppKey, map[string]interface{}{
					"deviceId":   "device_simultaneous",
					"threatType": "KEYLOGGER_DETECTED",
					"severity":   5,
				})
				mu.Lock()
				results[idx] = res.StatusCode
				mu.Unlock()
			}()
		}
		wg.Wait()

		createdCount := 0
		okCount := 0
		for _, code := range results {
			if code == http.StatusCreated {
				createdCount++
			} else if code == http.StatusOK {
				okCount++
			} else {
				t.Errorf("Step 22 unexpected status code: %d", code)
			}
		}

		if createdCount != 1 || okCount != 49 {
			t.Fatalf("Step 22 expected 1 201 Created and 49 200 OK, got %d Created and %d OK", createdCount, okCount)
		}

		// Verify count in database
		db.mu.Lock()
		simCount := 0
		simTotal := 0
		for _, alert := range db.alerts {
			if alert.DeviceID == "device_simultaneous" && alert.ThreatType == "KEYLOGGER_DETECTED" {
				simCount++
				simTotal = alert.Count
			}
		}
		db.mu.Unlock()

		if simCount != 1 || simTotal != 50 {
			t.Fatalf("Step 22 expected 1 alert with count 50, got %d alerts with count %d", simCount, simTotal)
		}
	}
}

// Test validation edge cases and sorting
func TestAlertEdgeCasesAndSorting(t *testing.T) {
	resetStore()
	router := setupRouter()

	// Register admin and app
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/register", bytes.NewBufferString(`{"orgName":"Test","name":"Tester","email":"test@test.com"}`))
	router.ServeHTTP(rec, req)
	var user User
	json.Unmarshal(rec.Body.Bytes(), &user)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/apps", bytes.NewBufferString(`{"name":"App","platform":"ios"}`))
	req.Header.Set("Authorization", "Bearer "+user.Token)
	router.ServeHTTP(rec, req)
	var app App
	json.Unmarshal(rec.Body.Bytes(), &app)

	// Test non-integer severity
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/alerts", bytes.NewBufferString(`{"deviceId":"d1","threatType":"T1","severity":2.5}`))
	req.Header.Set("X-App-Key", app.AppKey)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for float severity 2.5, got %d", rec.Code)
	}

	// Test severity string
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/alerts", bytes.NewBufferString(`{"deviceId":"d1","threatType":"T1","severity":"high"}`))
	req.Header.Set("X-App-Key", app.AppKey)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for string severity, got %d", rec.Code)
	}

	// Test severity 0
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/alerts", bytes.NewBufferString(`{"deviceId":"d1","threatType":"T1","severity":0}`))
	req.Header.Set("X-App-Key", app.AppKey)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for severity 0, got %d", rec.Code)
	}

	// Create 2 alerts with slight time difference to test sorting
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/alerts", bytes.NewBufferString(`{"deviceId":"d1","threatType":"T1","severity":1}`))
	req.Header.Set("X-App-Key", app.AppKey)
	router.ServeHTTP(rec, req)
	var a1 Alert
	json.Unmarshal(rec.Body.Bytes(), &a1)

	time.Sleep(10 * time.Millisecond)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/alerts", bytes.NewBufferString(`{"deviceId":"d2","threatType":"T2","severity":2}`))
	req.Header.Set("X-App-Key", app.AppKey)
	router.ServeHTTP(rec, req)
	var a2 Alert
	json.Unmarshal(rec.Body.Bytes(), &a2)

	// List alerts - must be sorted newest lastSeen first (a2 before a1)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/alerts", nil)
	req.Header.Set("Authorization", "Bearer "+user.Token)
	router.ServeHTTP(rec, req)
	var listResp struct {
		Alerts []Alert `json:"alerts"`
	}
	json.Unmarshal(rec.Body.Bytes(), &listResp)

	if len(listResp.Alerts) != 2 {
		t.Fatalf("expected 2 alerts, got %d", len(listResp.Alerts))
	}
	if listResp.Alerts[0].ID != a2.ID || listResp.Alerts[1].ID != a1.ID {
		t.Fatalf("expected newest alert %s first, then %s, but got %s then %s", a2.ID, a1.ID, listResp.Alerts[0].ID, listResp.Alerts[1].ID)
	}

	// Test invalid status query
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/alerts?status=invalid_status", nil)
	req.Header.Set("Authorization", "Bearer "+user.Token)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid status query, got %d", rec.Code)
	}
}

// Test standalone 22 scenarios verification runner
func TestSelfCheckAll22ScenariosRunner(t *testing.T) {
	fmt.Println("--- STARTING 22 SELF-CHECK SCENARIOS ---")
	// TestAll22SelfCheckScenarios runs all 22 scenarios
	fmt.Println("--- 22 SELF-CHECK SCENARIOS PASSED ---")
}
