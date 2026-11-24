# Threat Alert API

A lightweight, high-performance in-memory Threat Alert API written in Go, adhering strictly to standard library specifications, multi-tenant isolation, thread safety, and RBAC security.

---

## How to run

### Prerequisites
- Go 1.22 or newer (Tested on Go 1.27.4 windows/amd64).
- No external packages or third-party dependencies required.

### Starting the Server

The server starts by default on port `8080` (or the port defined by the `PORT` environment variable).

#### Linux / macOS
```bash
go run .
```
Or with a custom port:
```bash
PORT=9090 go run .
```

#### Windows (PowerShell)
```powershell
go run .
```
Or with a custom port in PowerShell:
```powershell
$env:PORT="9090"
go run .
```

### Running Tests

Execute formatting, static analysis, automated unit/integration tests, and race condition detection:

#### Run Standard Unit and Self-Check Tests
```powershell
go test -v ./...
```

#### Run Concurrency and Race Detector
```powershell
go test -race -v ./...
```

#### Format Code and Run Static Vetting
```powershell
gofmt -w .
go vet ./...
```

---

## Project structure

- `main.go`: Initializes HTTP routing via `http.ServeMux`, reads the `PORT` environment variable, and starts the HTTP server.
- `models.go`: Declares data structures for `Company`, `User`, `App`, and `Alert` with JSON mapping tags.
- `store.go`: Implements thread-safe in-memory storage, synchronized with `sync.Mutex`, along with ID sequence generators.
- `auth.go`: Provides cryptographic secret generation via `crypto/rand`, token authentication, app key authentication, and admin authorization checks.
- `handlers.go`: Implements the 7 HTTP REST endpoints (`/register`, `/users`, `/apps`, `/alerts`, `/alerts/{id}`, `/alerts/{id}/resolve`).
- `helpers.go`: Utility functions for JSON response encoding, strict request decoding, error responses, and email validation.
- `handlers_test.go`: Unit and integration tests covering the 3 mandatory tests (R9), sorting, validation, and edge cases.
- `self_check_test.go`: End-to-end integration test validating all 22 assignment self-check scenarios sequentially against a real HTTP server.
- `go.mod`: Go module declaration (`threat-alert-api`) with zero third-party dependencies.

---

## What works and what does not

### What Works
- **Strict Standard Library Compliance (R1)**: Built entirely with Go standard library (`net/http`, `crypto/rand`, `sync`, `encoding/json`). Zero third-party packages.
- **Server Execution and Port Configuration (R2)**: Starts smoothly with `go run .` and reads the `PORT` environment variable with fallback to `8080`.
- **Exact Routing and Status Codes (R3 & R4)**: All routes match exact paths, methods, and JSON error response format `{"error": "..."}`.
- **Strict Security Evaluation Pipeline (R5)**: Enforces Authentication -> Authorization -> Input Validation -> Record Existence.
- **Complete Company Isolation (R6)**: Cross-tenant resource access always returns HTTP 404 to prevent resource enumeration.
- **Cryptographically Secure Entropy (R7)**: All tokens and app keys are generated with 32 random bytes from `crypto/rand`, hex-encoded (64 characters).
- **Thread-Safe Alert Deduplication (R8)**: Mutex-locked critical section ensures 50 simultaneous identical alert requests produce exactly 1 alert with count 50.
- **Automated Testing Suite (R9)**: Tests viewer 403 authorization, cross-company 404 isolation, and 50 concurrent requests.
- **UTC Timestamps (R10)**: All timestamps are recorded in UTC and serialized in RFC3339 format.
- **All 22 Self-Check Scenarios**: 100% passed in both unit testing and end-to-end loopback HTTP testing.
- **Alert Sorting**: Alerts in `GET /alerts` are sorted newest `lastSeen` first, with ID tie-breaking.

### What Does Not / Known Limitations
- **In-Memory Volatility**: Data is stored purely in-memory; restarting the server clears all companies, users, apps, and alerts (as specified by assignment guidelines).
- **Single-Node Architecture**: Synchronization uses an in-process `sync.Mutex`. Multi-instance horizontal scaling would require external distributed locking or a shared persistent datastore.

---

## How AI helped

### Tools I used
- **Google Antigravity**: AI assistant used for codebase inspection, test scenario design, and auditing requirements compliance.
- **Go Standard Toolchain**: `go run`, `go test`, `go vet`, `gofmt`.

### Two prompts I used
1. *"Audit the Threat Alert API against requirements R1-R10 and identify why list alerts sorting and email validation fail edge cases."*
2. *"Implement concurrent alert deduplication and verify thread safety for 50 simultaneous identical requests using sync.Mutex."*

### One thing AI got wrong and how it was identified and fixed
The AI initially sorted alerts in `listAlertsHandler` using `alerts[i].LastSeen.Before(alerts[j].LastSeen)`, which sorted alerts oldest first instead of newest first. During code audit against requirement 5 (*"Sort newest lastSeen first"*), this inversion was identified and corrected to `alerts[i].LastSeen.After(alerts[j].LastSeen)` with an ID tie-breaker for identical timestamps.

### One part I wrote or changed myself without AI
I designed the in-memory store schema in `store.go`, configured the endpoint routes in `setupRouter()`, and defined the multi-tenant ID mapping logic between tokens, users, and companies.

---

## Questions

### 1. Two identical alerts arrive at the same moment. Point to the exact lines in the code that guarantee only one alert is created.

In `handlers.go`:
- **Line 218 (`db.mu.Lock()`) and Line 219 (`defer db.mu.Unlock()`)**: An exclusive mutex lock guards the entire critical section of alert lookup and insertion.
- **Lines 223–236**: The handler scans `db.alerts` to check if an open alert exists for the same `AppID`, `DeviceID`, and `ThreatType`.
- **Lines 238–254**: If no matching open alert is found, a new alert is instantiated and inserted into `db.alerts`.

**Execution Guarantee:**
When two identical requests arrive simultaneously, Go's runtime forces one request to acquire `db.mu.Lock()` on Line 218 while the second waits. The first request searches `db.alerts`, finds no existing record, creates the alert with `count: 1`, inserts it into `db.alerts[alert.ID]`, and releases the lock. When the second request acquires the lock, its search on Lines 223–227 finds the alert already created by the first request. It executes Lines 229–234, incrementing `Count` to 2 and updating `LastSeen`, returning HTTP 200 without creating a duplicate alert.

### 2. Why does a user from another company get 404 and not 403?

Returning **HTTP 403 Forbidden** would inform the caller that the resource exists, but they lack permission to view it. This introduces an **information disclosure / resource enumeration vulnerability**, allowing malicious actors or competing tenants to brute-force alert IDs and confirm the existence of security incidents in other organizations.

By returning **HTTP 404 Not Found**, the API treats cross-tenant resources as non-existent to unauthorized callers, strictly preserving tenant data isolation and preventing multi-tenant data leakage.
