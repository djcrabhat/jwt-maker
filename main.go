package main

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/penglongli/gin-metrics/ginmetrics"
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
	Subject   string `form:"sub" json:"sub" xml:"sub"  binding:"required"`
}

type WellKnownOidc struct {
	Issuer string `json:"issuer"`
	//AuthURL     string   `json:"authorization_endpoint"`
	//TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	Algorithms  []string `json:""`
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

	key, err := jwk.FromRaw(prvKey.PublicKey)
	if err != nil {
		fmt.Printf("failed to create symmetric key: %s\n", err)
		return
	}
	if _, ok := key.(jwk.RSAPublicKey); !ok {
		fmt.Printf("expected jwk.RSAPublicKey, got %T\n", key)
		return
	}

	externalUrl := "http://localhost:8000"
	//TODO: get hostname from config
	server01 := &http.Server{
		Addr:         ":8000",
		Handler:      publicRouter(externalUrl, key),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	server02 := &http.Server{
		Addr:         ":8001",
		Handler:      privateRouter(prvKey, externalUrl),
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

func publicRouter(externalUrl string, key jwk.Key) http.Handler {
	e := gin.New()
	e.Use(gin.Recovery())
	e.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	// TODO: get external hostname
	e.GET("/.well-known/openid-configuration", func(c *gin.Context) {
		c.JSON(http.StatusOK, WellKnownOidc{
			Issuer:      externalUrl,
			Algorithms:  []string{"RS512"},
			JWKSURL:     externalUrl + "/.well-known/keys",
			UserInfoURL: externalUrl + "/userinfo",
		})
	})
	e.GET("/.well-known/keys", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"keys": []interface{}{key},
		})
	})
	return e
}

func privateRouter(prvKey *rsa.PrivateKey, externalUrl string) http.Handler {
	e := gin.New()

	m := ginmetrics.GetMonitor()
	// +optional set metric path, default /debug/metrics
	m.SetMetricPath("/metrics")
	// +optional set slow time, default 5s
	m.SetSlowTime(10)
	// +optional set request duration, default {0.1, 0.3, 1.2, 5, 10}
	// used to p95, p99
	m.SetDuration([]float64{0.1, 0.3, 1.2, 5, 10})

	// set middleware for gin
	m.Use(e)

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
		tokenString, _ := generateToken(prvKey, req, externalUrl)
		c.JSON(http.StatusOK, gin.H{
			"token": tokenString,
		})
	})
	return e
}

func generateToken(prvKey *rsa.PrivateKey, req TokenRequest, issuerUrl string) (string, error) {
	claims := &JobToken{
		JobId:     req.Job,
		Namespace: req.Namespace,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuerUrl,
			Subject:   req.Subject,
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
