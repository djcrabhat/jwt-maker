package main

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/spf13/viper"

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

var (
	g errgroup.Group
)

func loadConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.SetEnvPrefix("jwt")
	viper.SetDefault("private_key", "cert/id_rsa")
	viper.SetDefault("external_url", "http://localhost:8000")

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if desired
		} else {
			// Config file was found but another error was produced
		}
	}
}

func main() {
	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	loadConfig()
	prvKey, err := loadRsaPrivateKey(viper.GetString("private_key"))
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
	jwk.AssignKeyID(key)

	externalUrl := viper.GetString("external_url")

	server01 := &http.Server{
		Addr:         ":8000",
		Handler:      publicRouter(externalUrl, key),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	server02 := &http.Server{
		Addr:         ":8001",
		Handler:      privateRouter(prvKey, externalUrl, key),
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

func privateRouter(prvKey *rsa.PrivateKey, externalUrl string, key jwk.Key) http.Handler {
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
			req.Audience = "jwt-maker"
		}
		tokenString, _ := generateToken(prvKey, req, externalUrl, key)
		c.JSON(http.StatusOK, gin.H{
			"token": tokenString,
		})
	})
	return e
}

func generateToken(prvKey *rsa.PrivateKey, req TokenRequest, issuerUrl string, jwkPublic jwk.Key) (string, error) {
	// TODO: make expire window configurable
	duration := 24 * time.Hour
	if req.TokenDuration != "" {
		var parseErr error
		duration, parseErr = time.ParseDuration(req.TokenDuration)
		if parseErr != nil {
			duration = 24 * time.Hour
		}
	}
	expires := time.Now().Add(duration)

	// build a MapClaims instead of a more convenient strongly typed one, so we can build in arbitrary claims at request time
	rawClaims := jwt.MapClaims{}
	for k, v := range req.ExtraClaims {
		rawClaims[k] = v
	}
	rawClaims["iss"] = issuerUrl
	rawClaims["sub"] = req.Subject
	rawClaims["exp"] = jwt.NewNumericDate(expires)
	rawClaims["iat"] = jwt.NewNumericDate(time.Now())
	rawClaims["nbf"] = jwt.NewNumericDate(time.Now())
	rawClaims["aud"] = []string{req.Audience}
	if len(req.Claims) > 0 {
		rawClaims["claims"] = req.Claims
	}
	if len(req.Roles) > 0 {
		rawClaims["roles"] = req.Roles

	}
	if req.Namespace != "" {
		rawClaims["ns"] = req.Namespace
	}
	if req.Job != "" {
		rawClaims["job"] = req.Job
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS512, rawClaims)
	token.Header["kid"] = jwkPublic.KeyID()

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(prvKey)
	if err != nil {
		return "", err
	}
	return tokenString, err
}
