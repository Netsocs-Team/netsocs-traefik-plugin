package netsocs_traefik_plugin

// package netsocs_traefik_plugin

// import (
// 	"context"
// 	"encoding/json"
// 	"fmt"
// 	"net/http"
// 	"time"
// )

// // Config the plugin configuration.
// type Config struct {
// 	AccessControlApi string
// 	CookieName       string
// 	LicenseApi       string
// }

// // CreateConfig creates the default plugin configuration.
// func CreateConfig() *Config {
// 	return &Config{}
// }

// type Person struct {
// 	ID                         string        `json:"id"`
// 	Name                       string        `json:"name"`
// 	Photo                      string        `json:"photo"`
// 	Type                       string        `json:"type"`
// 	IdentificationDocument     string        `json:"identification_document"`
// 	IdentificationDocumentType string        `json:"identification_document_type"`
// 	Email                      string        `json:"email"`
// 	AccessLevels               []interface{} `json:"access_levels"`
// 	Phone                      string        `json:"phone"`
// 	Vehicles                   []interface{} `json:"vehicles"`
// 	ActivationDate             string        `json:"activation_date"`
// 	ExpirationDate             string        `json:"expiration_date"`
// 	Lists                      []interface{} `json:"lists"`
// 	Signature                  string        `json:"signature"`
// 	Attachments                []interface{} `json:"attachments"`
// 	Departments                []interface{} `json:"departments"`
// 	Disabled                   bool          `json:"disabled"`
// 	CreatedAt                  time.Time     `json:"created_at"`
// 	UpdatedAt                  time.Time     `json:"updated_at"`
// }

// type NetsocsUserSession struct {
// 	next             http.Handler
// 	AccessControlApi string
// 	CookieName       string
// 	LicenseApi       string
// }

// // New created a new Demo plugin.
// func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
// 	return &NetsocsUserSession{
// 		next:             next,
// 		AccessControlApi: config.AccessControlApi,
// 		CookieName:       config.CookieName,
// 		LicenseApi:       config.LicenseApi,
// 	}, nil
// }

// func (a *NetsocsUserSession) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
// 	license := CheckLicense(a.LicenseApi)
// 	if !license {
// 		http.Redirect(rw, req, "/n/config", http.StatusFound)
// 		return
// 	}
// 	err := SyncUserSession(req.Context(), req, rw, a.CookieName, a.AccessControlApi)
// 	if err != nil {
// 		http.Redirect(rw, req, "/", http.StatusFound)
// 		return
// 	}

// 	a.next.ServeHTTP(rw, req)
// }

// func SyncUserSession(ctx context.Context, req *http.Request, rw http.ResponseWriter,
// 	cookieName string, accessControlApi string) error {
// 	cookie, err := req.Cookie(cookieName)
// 	if err == nil {
// 		user, err := CheckUser(cookie.Value, accessControlApi, cookieName)
// 		if err != nil {
// 			return fmt.Errorf("error checking user: %v", err)
// 		}

// 		if len(user.Departments) == 0 {
// 			http.Redirect(rw, req, "/n/access_control/host", http.StatusFound)
// 		}

// 	} else if err == http.ErrNoCookie {
// 		return fmt.Errorf("cookie not found")
// 	} else {
// 		return err
// 	}

// 	return nil
// }

// func CheckLicense(licenseApi string) bool {
// 	url := fmt.Sprintf("%s/license", licenseApi)
// 	req, err := http.NewRequest("GET", url, nil)
// 	if err != nil {
// 		return false
// 	}
// 	client := &http.Client{}
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		return false
// 	}
// 	defer resp.Body.Close()
// 	return resp.StatusCode == http.StatusOK
// }

// func CheckUser(netsocstoken string, accesControlApi string, cookieName string) (Person, error) {
// 	url := fmt.Sprintf("%s/check_user", accesControlApi)
// 	req, err := http.NewRequest("GET", url, nil)
// 	if err != nil {
// 		return Person{}, err
// 	}
// 	req.Header.Set("Cookie", fmt.Sprintf("%s=%s", cookieName, netsocstoken))
// 	client := &http.Client{}
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		return Person{}, err
// 	}
// 	defer resp.Body.Close()
// 	if resp.StatusCode != http.StatusOK {
// 		return Person{}, fmt.Errorf("failed to check user: %s", resp.Status)
// 	}
// 	var user Person
// 	err = json.NewDecoder(resp.Body).Decode(&user)

// 	if err != nil {
// 		return Person{}, err
// 	}
// 	if user.ID == "" {
// 		return Person{}, fmt.Errorf("user not found")
// 	}
// 	return user, nil

// }

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (k *keycloakAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	for _, substr := range k.IgnorePathPrefixes {
		if strings.Contains(req.URL.Path, substr) {
			k.next.ServeHTTP(rw, req)
			return
		}
	}
	cookie, err := req.Cookie("Authorization")
	if err == nil && strings.HasPrefix(cookie.Value, "Bearer ") {
		token := strings.TrimPrefix(cookie.Value, "Bearer ")
		fmt.Printf("token = %+v\n", token)

		ok, err := k.verifyToken(token)
		fmt.Printf("ok = %+v\n", ok)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		if !ok {
			qry := req.URL.Query()
			qry.Del("code")
			qry.Del("state")
			qry.Del("session_state")
			req.URL.RawQuery = qry.Encode()
			req.RequestURI = req.URL.RequestURI()

			expiration := time.Now().Add(-24 * time.Hour)
			newCookie := &http.Cookie{
				Name:    "Authorization",
				Value:   "",
				Path:    "/",
				Expires: expiration,
				MaxAge:  -1,
			}
			http.SetCookie(rw, newCookie)

			k.redirectToKeycloak(rw, req)
			return
		}
		user, err := extractClaims(token, k.UserClaimName)
		if err == nil {
			req.Header.Set(k.UserHeaderName, user)
		}

		if k.UseAuthHeader {
			// Optionally set the Bearer token to the Authorization header.
			req.Header.Set("Authorization", "Bearer "+token)
		}

		k.next.ServeHTTP(rw, req)
	} else {
		authCode := req.URL.Query().Get("code")
		if authCode == "" {
			fmt.Printf("code is missing, redirect to keycloak\n")
			k.redirectToKeycloak(rw, req)
			return
		}

		stateBase64 := req.URL.Query().Get("state")
		if stateBase64 == "" {
			fmt.Printf("state is missing, redirect to keycloak\n")
			k.redirectToKeycloak(rw, req)
			return
		}

		fmt.Printf("exchange auth code called\n")
		token, err := k.exchangeAuthCode(req, authCode, stateBase64)
		fmt.Printf("exchange auth code finished %+v\n", token)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		if k.UseAuthHeader {
			// Optionally set the Bearer token to the Authorization header.
			req.Header.Set("Authorization", "Bearer "+token)
		}

		authCookie := &http.Cookie{
			Name:     "Authorization",
			Value:    "Bearer " + token,
			Secure:   true,
			HttpOnly: true,
			Path:     "/",
			SameSite: http.SameSiteLaxMode, // Allows requests originating from sibling domains (same parent diff sub domain) to access the cookie
		}

		tokenCookie := &http.Cookie{
			Name:     k.TokenCookieName, // Defaults to "AUTH_TOKEN"
			Value:    token,
			Secure:   true,
			HttpOnly: true,
			Path:     "/",
			SameSite: http.SameSiteLaxMode, // Allows requests originating from sibling domains (same parent diff sub domain) to access the cookie
		}

		http.SetCookie(rw, authCookie)
		req.AddCookie(authCookie) // Add the cookie to the request so it is present on the redirect and prevents infite loop of redirects.

		// Set the token to a default/custom cookie that doesnt require trimming the Bearer prefix for common integration compatibility
		http.SetCookie(rw, tokenCookie)
		req.AddCookie(tokenCookie) // Add the cookie to the request so it is present on the initial redirect below.

		qry := req.URL.Query()
		qry.Del("code")
		qry.Del("state")
		qry.Del("session_state")
		req.URL.RawQuery = qry.Encode()
		req.RequestURI = req.URL.RequestURI()

		scheme := req.Header.Get("X-Forwarded-Proto")
		host := req.Header.Get("X-Forwarded-Host")
		originalURL := fmt.Sprintf("%s://%s%s", scheme, host, req.RequestURI)

		http.Redirect(rw, req, originalURL, http.StatusTemporaryRedirect)
	}
}

func extractClaims(tokenString string, claimName string) (string, error) {
	jwtContent := strings.Split(tokenString, ".")
	if len(jwtContent) < 3 {
		return "", fmt.Errorf("malformed jwt")
	}

	var jwtClaims map[string]interface{}
	decoder := base64.StdEncoding.WithPadding(base64.NoPadding)

	jwt_bytes, _ := decoder.DecodeString(jwtContent[1])
	if err := json.Unmarshal(jwt_bytes, &jwtClaims); err != nil {
		return "", err
	}

	if claimValue, ok := jwtClaims[claimName]; ok {
		return fmt.Sprintf("%v", claimValue), nil
	}
	return "", fmt.Errorf("missing claim %s", claimName)
}

func (k *keycloakAuth) exchangeAuthCode(req *http.Request, authCode string, stateBase64 string) (string, error) {
	stateBytes, _ := base64.StdEncoding.DecodeString(stateBase64)
	var state state
	err := json.Unmarshal(stateBytes, &state)
	if err != nil {
		return "", err
	}

	target := k.KeycloakURL.JoinPath(
		"realms",
		k.KeycloakRealm,
		"protocol",
		"openid-connect",
		"token",
	)
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: k.InsecureSkipVerify}

	resp, err := http.PostForm(target.String(),
		url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {k.ClientID},
			"client_secret": {k.ClientSecret},
			"code":          {authCode},
			"redirect_uri":  {state.RedirectURL},
		})

	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", errors.New("received bad response from Keycloak: " + string(body))
	}

	var tokenResponse KeycloakTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	if err != nil {
		return "", err
	}

	return tokenResponse.AccessToken, nil
}

func (k *keycloakAuth) redirectToKeycloak(rw http.ResponseWriter, req *http.Request) {
	scheme := req.Header.Get("X-Forwarded-Proto")
	host := req.Header.Get("X-Forwarded-Host")
	originalURL := fmt.Sprintf("%s://%s%s", scheme, host, req.RequestURI)

	state := state{
		RedirectURL: originalURL,
	}

	stateBytes, _ := json.Marshal(state)
	stateBase64 := base64.StdEncoding.EncodeToString(stateBytes)

	redirectURL := k.KeycloakURL.JoinPath(
		"realms",
		k.KeycloakRealm,
		"protocol",
		"openid-connect",
		"auth",
	)
	redirectURL.RawQuery = url.Values{
		"response_type": {"code"},
		"client_id":     {k.ClientID},
		"redirect_uri":  {originalURL},
		"state":         {stateBase64},
		"scope":         {k.Scope},
	}.Encode()

	http.Redirect(rw, req, redirectURL.String(), http.StatusTemporaryRedirect)
}

func (k *keycloakAuth) verifyToken(token string) (bool, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: k.InsecureSkipVerify},
	}

	client := &http.Client{Transport: tr}

	data := url.Values{
		"token": {token},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		k.KeycloakURL.JoinPath(
			"realms",
			k.KeycloakRealm,
			"protocol",
			"openid-connect",
			"token",
			"introspect",
		).String(),
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return false, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(k.ClientID, k.ClientSecret)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var introspectResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&introspectResponse)
	if err != nil {
		return false, err
	}

	return introspectResponse["active"].(bool), nil
}
