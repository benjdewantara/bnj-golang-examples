package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
	//"golang.org/x/oauth2/github"
	//"golang.org/x/oauth2/github"
)

var (
	clientID     = ""
	clientSecret = ""
	redirectURL  = "http://localhost:8080/callback"
)

var (
	// Cache for storing state
	stateCache                 = cache.New(10*time.Minute, 20*time.Minute)
	codeVerifierChallengeCache = cache.New(10*time.Minute, 20*time.Minute)

	// OAuth2 configuration
	oauth2Config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     endpoints.AzureAD(""),
		Scopes:       []string{"openid", "email", "profile"},
	}

	// GitHub user information API
	userInfoURL = "https://api.github.com/user"
)

func generateRandomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

type GitHubUser struct {
	ID        int    `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

type CodeVerifierChallengePair struct {
	CodeVerifier  string
	CodeChallenge string
}

//go:embed templates/*
var templatesFS embed.FS

func main() {
	r := gin.Default()

	// Set HTML templates
	r.SetHTMLTemplate(template.Must(template.ParseFS(templatesFS, "templates/*")))

	// Home route
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"title": "GitHub OAuth Example",
		})
	})

	// Login route - Redirect to GitHub for authentication
	r.GET("/login", func(c *gin.Context) {
		state, err := generateRandomState()
		if err != nil {
			c.String(http.StatusInternalServerError, "Unable to generate state value")
			return
		}

		// Store state for later verification

		codeVerifier := generateCodeVerifier()
		codeChallenge := generateCodeChallenge(codeVerifier)
		codeVerifierChallengeCache.Add(codeChallenge, codeVerifier, 10*time.Minute)
		verifierChallengePair :=
			CodeVerifierChallengePair{
				CodeVerifier:  codeVerifier,
				CodeChallenge: codeChallenge,
			}
		stateCache.Set(state, verifierChallengePair, cache.DefaultExpiration)

		// Redirect to GitHub for authentication
		authURL := oauth2Config.AuthCodeURL(
			state,
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
			//oauth2.SetAuthURLParam("response_type", "id_token"),
			//oauth2.SetAuthURLParam("nonce", "1234"),
		)
		c.Redirect(http.StatusFound, authURL)
	},
	)

	// Callback route - Handle GitHub authentication callback
	r.GET("/callback", func(c *gin.Context) {
		// Retrieve and verify state
		state := c.Query("state")
		cachedValue, exists := stateCache.Get(state)
		if !exists {
			c.String(http.StatusBadRequest, "Invalid state value")
			return
		}
		stateCache.Delete(state)

		codeVerifierChallenge := cachedValue.(CodeVerifierChallengePair)
		_ = codeVerifierChallenge

		// Retrieve code
		code := c.Query("code")
		if code == "" {
			c.String(http.StatusBadRequest, "Authorization code not provided")
			return
		}

		// Exchange code for access token
		token, err := oauth2Config.Exchange(context.Background(),
			code,
			oauth2.SetAuthURLParam("grant_type", "authorization_code"),
			oauth2.SetAuthURLParam("code_verifier", codeVerifierChallenge.CodeVerifier),
			oauth2.SetAuthURLParam("code", code),
			oauth2.SetAuthURLParam("client_id", clientID),
			oauth2.SetAuthURLParam("redirect_uri", "http://localhost:8080/callback"),
		)
		if err != nil {
			c.String(
				http.StatusInternalServerError,
				"Unable to exchange access token: "+err.Error(),
			)
			return
		}

		// Use access token to get user information
		client := oauth2Config.Client(context.Background(), token)
		resp, err := client.Get(userInfoURL)
		if err != nil {
			c.String(
				http.StatusInternalServerError,
				"Unable to retrieve user information: "+err.Error(),
			)
			return
		}
		defer resp.Body.Close()

		var user GitHubUser
		if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
			c.String(
				http.StatusInternalServerError,
				"Unable to parse user information: "+err.Error(),
			)
			return
		}

		// Display user information on success page
		c.HTML(http.StatusOK, "success.html", gin.H{
			"title":      "Authentication Successful",
			"username":   user.Login,
			"name":       user.Name,
			"email":      user.Email,
			"avatar_url": user.AvatarURL,
		})
	})

	// Protected route - Requires authentication to access
	r.GET("/protected", func(c *gin.Context) {
		// In a real application, session or JWT token should be checked here
		// This is just a simplified example
		c.String(http.StatusOK, "This is a protected resource!")
	})

	// Start server
	log.Println("Server running at http://localhost:8080")
	r.Run(":8080")
}

func generateCodeVerifier() string {
	bytesRandom := make([]byte, 32)
	rand.Read(bytesRandom)

	stringCodeVerifier := base64.URLEncoding.EncodeToString(bytesRandom)
	stringCodeVerifier = strings.TrimSuffix(stringCodeVerifier, "=")
	stringCodeVerifier = strings.ReplaceAll(stringCodeVerifier, "+", "-")
	stringCodeVerifier = strings.ReplaceAll(stringCodeVerifier, "/", "_")

	return stringCodeVerifier
}

func generateCodeChallenge(codeVerifier string) string {
	bytesFixedLength := sha256.Sum256([]byte(codeVerifier))
	bytes := make([]byte, 32)
	for i := 0; i < 32; i++ {
		bytes[i] = bytesFixedLength[i]
	}

	stringCodeChallenge := base64.URLEncoding.EncodeToString(bytes)
	stringCodeChallenge = strings.TrimSuffix(stringCodeChallenge, "=")
	stringCodeChallenge = strings.ReplaceAll(stringCodeChallenge, "+", "-")
	stringCodeChallenge = strings.ReplaceAll(stringCodeChallenge, "/", "_")

	return stringCodeChallenge
}

func genCodeChallengeS256() (string, string) {
	charsUnreserved := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	lenUnreserved := int64(len(charsUnreserved))
	codeVerifier := ""
	for i := int64(0); i < lenUnreserved; i++ {
		ir, _ := rand.Int(rand.Reader, big.NewInt(lenUnreserved))
		codeVerifier += string(charsUnreserved[ir.Int64()])
	}
	s256 := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := fmt.Sprintf("%x", s256)
	return codeVerifier, codeChallenge
}
