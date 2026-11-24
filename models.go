package main

import "time"

type Company struct {
	OrgID   string `json:"orgId"`
	OrgName string `json:"orgName"`
}

type User struct {
	UserID string `json:"userId"`
	OrgID  string `json:"-"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	Token  string `json:"token"`
}

type App struct {
	AppID    string `json:"appId"`
	OrgID    string `json:"orgId"`
	Name     string `json:"name"`
	Platform string `json:"platform"`
	AppKey   string `json:"appKey"`
}

type Alert struct {
	ID         string    `json:"id"`
	OrgID      string    `json:"-"`
	AppID      string    `json:"appId"`
	DeviceID   string    `json:"deviceId"`
	ThreatType string    `json:"threatType"`
	Severity   int       `json:"severity"`
	Count      int       `json:"count"`
	Status     string    `json:"status"`
	FirstSeen  time.Time `json:"firstSeen"`
	LastSeen   time.Time `json:"lastSeen"`
	ResolvedBy string    `json:"resolvedBy"`
}
