package main

import "github.com/golang-jwt/jwt/v4"

type JobToken struct {
	JobId     string        `json:"job,omitempty"`
	Namespace string        `json:"ns,omitempty"`
	Claims    []string      `json:"claims,omitempty"`
	Roles     []interface{} `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

type TokenRequest struct {
	ExtraClaims   map[string]interface{} `json:"extra_claims"`
	Job           string                 `form:"job" json:"job" xml:"job"`
	Namespace     string                 `form:"ns" json:"ns" xml:"ns"`
	Audience      string                 `form:"aud" json:"aud" xml:"aud"`
	Claims        []string               `json:"claims"`
	Roles         []interface{}          `json:"roles"`
	TokenDuration string                 `form:"duration" json:"duration" xml:"duration"`
	Subject       string                 `form:"sub" json:"sub" xml:"sub"  binding:"required"`
}

type WellKnownOidc struct {
	Issuer string `json:"issuer"`
	//AuthURL     string   `json:"authorization_endpoint"`
	//TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	Algorithms  []string `json:""`
}
