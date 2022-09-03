package main

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/sync/errgroup"
	"log"
	"net/http"
	"os"
	"time"
)

func loadRsaPrivateKey(path string) (*rsa.PrivateKey, error) {
	privateKeyFile, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)
	data, _ := pem.Decode([]byte(pembytes))
	privateKeyFile.Close()
	privateKeyImported, err := x509.ParsePKCS1PrivateKey(data.Bytes)
	if err != nil {
		panic(err)
	}

	return privateKeyImported, err
}

type JobToken struct {
	JobId     string `json:"job"`
	Namespace string `json:"ns"`
	jwt.RegisteredClaims
}

type TokenRequest struct {
	Job       string `form:"job" json:"job" xml:"job"  binding:"required"`
	Namespace string `form:"ns" json:"ns" xml:"ns"  binding:"required"`
	Audience  string `form:"aud" json:"aud" xml:"aud"`
}

type WellKnownOidc struct {
	Issuer      string   `json:"issuer"`
	AuthURL     string   `json:"authorization_endpoint"`
	TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	Algorithms  []string `json:"id_token_signing_alg_values_supported"`
}

var (
	g errgroup.Group
)

func main() {
	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	prvKey, err := loadRsaPrivateKey("cert/id_rsa")
	if err != nil {
		log.Fatalln(err)
	}

	server01 := &http.Server{
		Addr:         ":8000",
		Handler:      publicRouter(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	server02 := &http.Server{
		Addr:         ":8001",
		Handler:      privateRouter(prvKey),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	g.Go(func() error {
		err := server01.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
		return err
	})

	g.Go(func() error {
		err := server02.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
		return err
	})

	if err := g.Wait(); err != nil {
		log.Fatal(err)
	}
}

func publicRouter() http.Handler {
	e := gin.New()
	e.Use(gin.Recovery())
	e.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	e.GET("/.well-known/openid-configuration", func(c *gin.Context) {
		c.JSON(http.StatusOK, WellKnownOidc{
			Algorithms: []string{"RS512"},
		})
	})
	return e
}

func privateRouter(prvKey *rsa.PrivateKey) http.Handler {
	e := gin.New()
	e.Use(gin.Recovery())
	e.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "private!",
		})
	})
	e.POST("/tokens/jobs/generate", func(c *gin.Context) {
		var req TokenRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if req.Audience == "" {
			req.Audience = "workflow"
		}
		tokenString, _ := generateToken(prvKey, req)
		c.JSON(http.StatusOK, gin.H{
			"token": tokenString,
		})
	})
	return e
}

func generateToken(prvKey *rsa.PrivateKey, req TokenRequest) (string, error) {
	claims := &JobToken{
		JobId:     req.Job,
		Namespace: req.Namespace,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Audience:  []string{req.Audience},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(prvKey)
	if err != nil {
		return "", err
	}
	return tokenString, err
}
