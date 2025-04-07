package netsocs_traefik_plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Config the plugin configuration.
type Config struct {
	AccessControlApi string
	CookieName       string
	LicenseApi       string
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

type Person struct {
	ID                         string        `json:"id"`
	Name                       string        `json:"name"`
	Photo                      string        `json:"photo"`
	Type                       string        `json:"type"`
	IdentificationDocument     string        `json:"identification_document"`
	IdentificationDocumentType string        `json:"identification_document_type"`
	Email                      string        `json:"email"`
	AccessLevels               []interface{} `json:"access_levels"`
	Phone                      string        `json:"phone"`
	Vehicles                   []interface{} `json:"vehicles"`
	ActivationDate             string        `json:"activation_date"`
	ExpirationDate             string        `json:"expiration_date"`
	Lists                      []interface{} `json:"lists"`
	Signature                  string        `json:"signature"`
	Attachments                []interface{} `json:"attachments"`
	Departments                []interface{} `json:"departments"`
	Disabled                   bool          `json:"disabled"`
	CreatedAt                  time.Time     `json:"created_at"`
	UpdatedAt                  time.Time     `json:"updated_at"`
}

type NetsocsUserSession struct {
	next             http.Handler
	AccessControlApi string
	CookieName       string
	LicenseApi       string
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &NetsocsUserSession{
		next:             next,
		AccessControlApi: config.AccessControlApi,
		CookieName:       config.CookieName,
		LicenseApi:       config.LicenseApi,
	}, nil
}

func (a *NetsocsUserSession) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	license := CheckLicense(a.LicenseApi)
	if !license {
		http.Redirect(rw, req, "/n/config", http.StatusFound)
		return
	}
	err := SyncUserSession(req.Context(), req, rw, a.CookieName, a.AccessControlApi)
	if err != nil {
		http.Redirect(rw, req, "/", http.StatusFound)
		return
	}

	a.next.ServeHTTP(rw, req)
}

func SyncUserSession(ctx context.Context, req *http.Request, rw http.ResponseWriter,
	cookieName string, accessControlApi string) error {
	cookie, err := req.Cookie(cookieName)
	if err == nil {
		user, err := CheckUser(cookie.Value, accessControlApi, cookieName)
		if err != nil {
			return fmt.Errorf("error checking user: %v", err)
		}

		if len(user.Departments) == 0 {
			http.Redirect(rw, req, "/n/access_control/host", http.StatusFound)
		}

	} else if err == http.ErrNoCookie {
		return fmt.Errorf("cookie not found")
	} else {
		return err
	}

	return nil
}

func CheckLicense(licenseApi string) bool {
	url := fmt.Sprintf("%s/license", licenseApi)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func CheckUser(netsocstoken string, accesControlApi string, cookieName string) (Person, error) {
	url := fmt.Sprintf("%s/check_user", accesControlApi)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return Person{}, err
	}
	req.Header.Set("Cookie", fmt.Sprintf("%s=%s", cookieName, netsocstoken))
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return Person{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Person{}, fmt.Errorf("failed to check user: %s", resp.Status)
	}
	var user Person
	err = json.NewDecoder(resp.Body).Decode(&user)

	if err != nil {
		return Person{}, err
	}
	if user.ID == "" {
		return Person{}, fmt.Errorf("user not found")
	}
	return user, nil

}
