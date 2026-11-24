package main

import "sync"

type Store struct {
	mu sync.Mutex

	companies map[string]Company
	users     map[string]User
	apps      map[string]App
	alerts    map[string]Alert

	userTokens map[string]string
	appKeys    map[string]string

	orgCounter   int
	userCounter  int
	appCounter   int
	alertCounter int
}

var db = Store{
	companies:  make(map[string]Company),
	users:      make(map[string]User),
	apps:       make(map[string]App),
	alerts:     make(map[string]Alert),
	userTokens: make(map[string]string),
	appKeys:    make(map[string]string),
}

func (s *Store) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.companies = make(map[string]Company)
	s.users = make(map[string]User)
	s.apps = make(map[string]App)
	s.alerts = make(map[string]Alert)
	s.userTokens = make(map[string]string)
	s.appKeys = make(map[string]string)

	s.orgCounter = 0
	s.userCounter = 0
	s.appCounter = 0
	s.alertCounter = 0
}

func (s *Store) nextOrgID() string {
	s.orgCounter++
	return "org_" + itoa(s.orgCounter)
}

func (s *Store) nextUserID() string {
	s.userCounter++
	return "usr_" + itoa(s.userCounter)
}

func (s *Store) nextAppID() string {
	s.appCounter++
	return "app_" + itoa(s.appCounter)
}

func (s *Store) nextAlertID() string {
	s.alertCounter++
	return "alr_" + itoa(s.alertCounter)
}
