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
)

// TestRealHTTPServer22SelfCheck verifies all 22 steps over real HTTP (TCP loopback)
func TestRealHTTPServer22SelfCheck(t *testing.T) {
	resetStore()
	ts := httptest.NewServer(setupRouter())
	defer ts.Close()

	client := ts.Client()

	sendReq := func(method, path string, token, appKey string, body interface{}) (int, []byte) {
		var bodyReader io.Reader
		if body != nil {
			data, _ := json.Marshal(body)
			bodyReader = bytes.NewReader(data)
		}
		req, err := http.NewRequest(method, ts.URL+path, bodyReader)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if appKey != "" {
			req.Header.Set("X-App-Key", appKey)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		respBytes, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, respBytes
	}

	var acmeAdminToken string
	var betaAdminToken string
	var acmeViewerToken string
	var acmeAppKey string
	var alert1ID string
	var alert2ID string

	// 1. Register Acme company — 201
	{
		status, body := sendReq("POST", "/register", "", "", map[string]string{
			"orgName": "Acme Corp",
			"name":    "Acme Admin",
			"email":   "admin@acme.com",
		})
		if status != 201 {
			t.Fatalf("Step 1 failed: expected 201, got %d: %s", status, string(body))
		}
		var user User
		json.Unmarshal(body, &user)
		acmeAdminToken = user.Token
		fmt.Printf("Step 1: Registered Acme company (201) - Token: %s...\n", acmeAdminToken[:12])
	}

	// 2. Register Beta company — 201
	{
		status, body := sendReq("POST", "/register", "", "", map[string]string{
			"orgName": "Beta Corp",
			"name":    "Beta Admin",
			"email":   "admin@beta.com",
		})
		if status != 201 {
			t.Fatalf("Step 2 failed: expected 201, got %d: %s", status, string(body))
		}
		var user User
		json.Unmarshal(body, &user)
		betaAdminToken = user.Token
		fmt.Printf("Step 2: Registered Beta company (201) - Token: %s...\n", betaAdminToken[:12])
	}

	// 3. Register with invalid email — 400
	{
		status, body := sendReq("POST", "/register", "", "", map[string]string{
			"orgName": "Invalid Org",
			"name":    "Invalid Admin",
			"email":   "not-an-email",
		})
		if status != 400 {
			t.Fatalf("Step 3 failed: expected 400, got %d: %s", status, string(body))
		}
		fmt.Printf("Step 3: Register with invalid email (400) - Response: %s\n", bytes.TrimSpace(body))
	}

	// 4. Acme admin creates viewer — 201
	{
		status, body := sendReq("POST", "/users", acmeAdminToken, "", map[string]string{
			"name":  "Acme Viewer",
			"email": "viewer@acme.com",
			"role":  "viewer",
		})
		if status != 201 {
			t.Fatalf("Step 4 failed: expected 201, got %d: %s", status, string(body))
		}
		var user User
		json.Unmarshal(body, &user)
		acmeViewerToken = user.Token
		fmt.Printf("Step 4: Acme admin creates viewer (201) - Token: %s...\n", acmeViewerToken[:12])
	}

	// 5. Viewer tries creating user — 403
	{
		status, body := sendReq("POST", "/users", acmeViewerToken, "", map[string]string{
			"name":  "Unauthorized User",
			"email": "unauth@acme.com",
			"role":  "viewer",
		})
		if status != 403 {
			t.Fatalf("Step 5 failed: expected 403, got %d: %s", status, string(body))
		}
		fmt.Printf("Step 5: Viewer tries creating user (403) - Response: %s\n", bytes.TrimSpace(body))
	}

	// 6. Create user without token — 401
	{
		status, body := sendReq("POST", "/users", "", "", map[string]string{
			"name":  "No Token User",
			"email": "notoken@acme.com",
			"role":  "viewer",
		})
		if status != 401 {
			t.Fatalf("Step 6 failed: expected 401, got %d: %s", status, string(body))
		}
		fmt.Printf("Step 6: Create user without token (401) - Response: %s\n", bytes.TrimSpace(body))
	}

	// 7. Acme admin creates Android app — 201
	{
		status, body := sendReq("POST", "/apps", acmeAdminToken, "", map[string]string{
			"name":     "Acme Android App",
			"platform": "android",
		})
		if status != 201 {
			t.Fatalf("Step 7 failed: expected 201, got %d: %s", status, string(body))
		}
		var app App
		json.Unmarshal(body, &app)
		acmeAppKey = app.AppKey
		fmt.Printf("Step 7: Acme admin creates Android app (201) - AppKey: %s...\n", acmeAppKey[:12])
	}

	// 8. Create app with Windows platform — 400
	{
		status, body := sendReq("POST", "/apps", acmeAdminToken, "", map[string]string{
			"name":     "Acme Windows App",
			"platform": "windows",
		})
		if status != 400 {
			t.Fatalf("Step 8 failed: expected 400, got %d: %s", status, string(body))
		}
		fmt.Printf("Step 8: Create app with Windows platform (400) - Response: %s\n", bytes.TrimSpace(body))
	}

	// 9. SDK creates first alert — 201, count 1
	{
		status, body := sendReq("POST", "/alerts", "", acmeAppKey, map[string]interface{}{
			"deviceId":   "dev-101",
			"threatType": "ROOT_DETECTED",
			"severity":   5,
		})
		if status != 201 {
			t.Fatalf("Step 9 failed: expected 201, got %d: %s", status, string(body))
		}
		var alert Alert
		json.Unmarshal(body, &alert)
		if alert.Count != 1 || alert.Status != "open" {
			t.Fatalf("Step 9 unexpected count or status: %v", alert)
		}
		alert1ID = alert.ID
		fmt.Printf("Step 9: SDK creates first alert (201) - Alert ID: %s, Count: %d\n", alert1ID, alert.Count)
	}

	// 10. Same threat again — 200, count 2, same ID
	{
		status, body := sendReq("POST", "/alerts", "", acmeAppKey, map[string]interface{}{
			"deviceId":   "dev-101",
			"threatType": "ROOT_DETECTED",
			"severity":   5,
		})
		if status != 200 {
			t.Fatalf("Step 10 failed: expected 200, got %d: %s", status, string(body))
		}
		var alert Alert
		json.Unmarshal(body, &alert)
		if alert.ID != alert1ID || alert.Count != 2 || alert.Status != "open" {
			t.Fatalf("Step 10 unexpected alert: %v", alert)
		}
		fmt.Printf("Step 10: Same threat again (200) - Alert ID: %s, Count: %d\n", alert.ID, alert.Count)
	}

	// 11. Severity 9 — 400
	{
		status, body := sendReq("POST", "/alerts", "", acmeAppKey, map[string]interface{}{
			"deviceId":   "dev-101",
			"threatType": "ROOT_DETECTED",
			"severity":   9,
		})
		if status != 400 {
			t.Fatalf("Step 11 failed: expected 400, got %d: %s", status, string(body))
		}
		fmt.Printf("Step 11: Severity 9 (400) - Response: %s\n", bytes.TrimSpace(body))
	}

	// 12. Wrong app key — 401
	{
		status, body := sendReq("POST", "/alerts", "", "wrong-app-key-999", map[string]interface{}{
			"deviceId":   "dev-101",
			"threatType": "ROOT_DETECTED",
			"severity":   3,
		})
		if status != 401 {
			t.Fatalf("Step 12 failed: expected 401, got %d: %s", status, string(body))
		}
		fmt.Printf("Step 12: Wrong app key (401) - Response: %s\n", bytes.TrimSpace(body))
	}

	// 13. Acme viewer lists alerts — 200, one alert
	{
		status, body := sendReq("GET", "/alerts", acmeViewerToken, "", nil)
		if status != 200 {
			t.Fatalf("Step 13 failed: expected 200, got %d: %s", status, string(body))
		}
		var resp struct {
			Alerts []Alert `json:"alerts"`
		}
		json.Unmarshal(body, &resp)
		if len(resp.Alerts) != 1 || resp.Alerts[0].ID != alert1ID {
			t.Fatalf("Step 13 expected 1 alert %s, got %v", alert1ID, resp.Alerts)
		}
		fmt.Printf("Step 13: Acme viewer lists alerts (200) - Found %d alert (%s)\n", len(resp.Alerts), resp.Alerts[0].ID)
	}

	// 14. Beta admin lists alerts — 200, empty list
	{
		status, body := sendReq("GET", "/alerts", betaAdminToken, "", nil)
		if status != 200 {
			t.Fatalf("Step 14 failed: expected 200, got %d: %s", status, string(body))
		}
		var resp struct {
			Alerts []Alert `json:"alerts"`
		}
		json.Unmarshal(body, &resp)
		if resp.Alerts == nil || len(resp.Alerts) != 0 {
			t.Fatalf("Step 14 expected empty alerts array, got %v", resp.Alerts)
		}
		fmt.Printf("Step 14: Beta admin lists alerts (200) - Isolated empty list: %s\n", bytes.TrimSpace(body))
	}

	// 15. Beta accesses Acme alert — 404
	{
		status, body := sendReq("GET", "/alerts/"+alert1ID, betaAdminToken, "", nil)
		if status != 404 {
			t.Fatalf("Step 15 failed: expected 404, got %d: %s", status, string(body))
		}
		fmt.Printf("Step 15: Beta accesses Acme alert (404) - Response: %s\n", bytes.TrimSpace(body))
	}

	// 16. Acme viewer resolves alert — 403
	{
		status, body := sendReq("POST", "/alerts/"+alert1ID+"/resolve", acmeViewerToken, "", nil)
		if status != 403 {
			t.Fatalf("Step 16 failed: expected 403, got %d: %s", status, string(body))
		}
		fmt.Printf("Step 16: Acme viewer resolves alert (403) - Response: %s\n", bytes.TrimSpace(body))
	}

	// 17. Beta admin resolves Acme alert — 404
	{
		status, body := sendReq("POST", "/alerts/"+alert1ID+"/resolve", betaAdminToken, "", nil)
		if status != 404 {
			t.Fatalf("Step 17 failed: expected 404, got %d: %s", status, string(body))
		}
		fmt.Printf("Step 17: Beta admin resolves Acme alert (404) - Response: %s\n", bytes.TrimSpace(body))
	}

	// 18. Acme admin resolves alert — 200
	{
		status, body := sendReq("POST", "/alerts/"+alert1ID+"/resolve", acmeAdminToken, "", nil)
		if status != 200 {
			t.Fatalf("Step 18 failed: expected 200, got %d: %s", status, string(body))
		}
		var alert Alert
		json.Unmarshal(body, &alert)
		if alert.Status != "resolved" || alert.ResolvedBy == "" {
			t.Fatalf("Step 18 expected resolved alert, got %v", alert)
		}
		fmt.Printf("Step 18: Acme admin resolves alert (200) - Status: %s, ResolvedBy: %s\n", alert.Status, alert.ResolvedBy)
	}

	// 19. Resolve same alert again — 409
	{
		status, body := sendReq("POST", "/alerts/"+alert1ID+"/resolve", acmeAdminToken, "", nil)
		if status != 409 {
			t.Fatalf("Step 19 failed: expected 409, got %d: %s", status, string(body))
		}
		fmt.Printf("Step 19: Resolve same alert again (409) - Response: %s\n", bytes.TrimSpace(body))
	}

	// 20. Same threat after resolution — 201, new alert ID, count 1
	{
		status, body := sendReq("POST", "/alerts", "", acmeAppKey, map[string]interface{}{
			"deviceId":   "dev-101",
			"threatType": "ROOT_DETECTED",
			"severity":   5,
		})
		if status != 201 {
			t.Fatalf("Step 20 failed: expected 201, got %d: %s", status, string(body))
		}
		var alert Alert
		json.Unmarshal(body, &alert)
		if alert.ID == alert1ID || alert.Count != 1 || alert.Status != "open" {
			t.Fatalf("Step 20 expected new alert ID with count 1, got %v", alert)
		}
		alert2ID = alert.ID
		fmt.Printf("Step 20: Same threat after resolution (201) - New Alert ID: %s, Count: %d\n", alert2ID, alert.Count)
	}

	// 21. List open alerts — 200
	{
		status, body := sendReq("GET", "/alerts?status=open", acmeAdminToken, "", nil)
		if status != 200 {
			t.Fatalf("Step 21 failed: expected 200, got %d: %s", status, string(body))
		}
		var resp struct {
			Alerts []Alert `json:"alerts"`
		}
		json.Unmarshal(body, &resp)
		if len(resp.Alerts) != 1 || resp.Alerts[0].ID != alert2ID {
			t.Fatalf("Step 21 expected 1 open alert (%s), got %v", alert2ID, resp.Alerts)
		}
		fmt.Printf("Step 21: List open alerts (200) - Found %d open alert (%s)\n", len(resp.Alerts), resp.Alerts[0].ID)
	}

	// 22. Send 50 identical alerts simultaneously — exactly one alert with count 50
	{
		var wg sync.WaitGroup
		statuses := make([]int, 50)
		var mu sync.Mutex

		for i := 0; i < 50; i++ {
			wg.Add(1)
			idx := i
			go func() {
				defer wg.Done()
				st, _ := sendReq("POST", "/alerts", "", acmeAppKey, map[string]interface{}{
					"deviceId":   "dev-stress-50",
					"threatType": "EMULATOR_DETECTED",
					"severity":   3,
				})
				mu.Lock()
				statuses[idx] = st
				mu.Unlock()
			}()
		}
		wg.Wait()

		createdCount := 0
		okCount := 0
		for _, s := range statuses {
			if s == 201 {
				createdCount++
			} else if s == 200 {
				okCount++
			} else {
				t.Errorf("Step 22 unexpected status: %d", s)
			}
		}

		if createdCount != 1 || okCount != 49 {
			t.Fatalf("Step 22 expected 1 201 Created and 49 200 OK, got %d Created and %d OK", createdCount, okCount)
		}

		// Verify alert in store
		db.mu.Lock()
		matchedAlerts := 0
		matchedCount := 0
		for _, a := range db.alerts {
			if a.DeviceID == "dev-stress-50" && a.ThreatType == "EMULATOR_DETECTED" {
				matchedAlerts++
				matchedCount = a.Count
			}
		}
		db.mu.Unlock()

		if matchedAlerts != 1 || matchedCount != 50 {
			t.Fatalf("Step 22 expected 1 alert with count 50, got %d alerts with count %d", matchedAlerts, matchedCount)
		}
		fmt.Printf("Step 22: Sent 50 simultaneous identical alerts - 1 Created (201), 49 Updated (200), Final Count: %d\n", matchedCount)
	}
}
