package crcauthlib

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/redhatinsights/crcauthlib/deps"
	identity "github.com/redhatinsights/platform-go-middlewares/v2/identity"
	"github.com/stretchr/testify/assert"
)

var testUser = User{
	Username:      "billy",
	Password:      "password",
	ID:            1234,
	Email:         "billy@billy.billy",
	FirstName:     "Billy",
	LastName:      "Bob",
	AccountNumber: "1",
	AddressString: "1",
	IsActive:      true,
	IsOrgAdmin:    true,
	IsInternal:    false,
	Locale:        "GB",
	OrgID:         "5432",
	DisplayName:   "Billy Bob",
	Type:          "User",
	Entitlements:  "",
}

type Claims struct {
	User
	jwt.RegisteredClaims
	Entitlements   []string `json:"newEntitlements"`
	ServiceAccount string   `json:"service_account,omitempty"`
}

func CreateJWT(xrhid *identity.XRHID) (string, error) {
	privateKeyBytes, err := os.ReadFile("test_files/private.pem")
	if err != nil {
		return "", fmt.Errorf("failed to read private key: %w", err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	var entitlements []string
	for k, v := range xrhid.Entitlements {
		entitlement, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("couldn't marshal entitlements: %w", err)

		}
		entitlements = append(entitlements, fmt.Sprintf("\"%s\": %s", k, entitlement))
	}

	claims := Claims{
		User: User{
			Username:      xrhid.Identity.User.Username,
			Email:         xrhid.Identity.User.Email,
			FirstName:     xrhid.Identity.User.FirstName,
			LastName:      xrhid.Identity.User.LastName,
			AccountNumber: xrhid.Identity.AccountNumber,
			IsActive:      false,
			IsOrgAdmin:    false,
			IsInternal:    false,
			Locale:        xrhid.Identity.User.Locale,
			OrgID:         xrhid.Identity.Internal.OrgID,
			Type:          "",
			Entitlements:  "",
		},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
			Issuer:    "your-issuer",
		},
		Entitlements: entitlements,
	}

	if xrhid.Identity.Type == "ServiceAccount" {
		claims.ServiceAccount = "true"
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

type MockHTTP struct {
	logic func() (*http.Response, error)
}

func (m *MockHTTP) Do(req *http.Request) (*http.Response, error) {
	if m.logic != nil {
		return m.logic()
	}
	return nil, errors.New("sup")
}

func (m *MockHTTP) Get(url string) (*http.Response, error) {
	if m.logic != nil {
		return m.logic()
	}
	return nil, errors.New("sup")
}

func HTTPBodyIsKey() (*http.Response, error) {
	io, err := os.Open("test_files/public.pem")
	if err != nil {
		return nil, err
	}
	resp := http.Response{
		Body: io,
	}
	return &resp, nil
}

func MockHTTPResponseIsUserJSON() (*http.Response, error) {
	io, _ := os.Open("test_files/test_user.json")
	resp := http.Response{
		Body:       io,
		StatusCode: 200,
	}
	return &resp, nil
}

func MockHTTPResponseIsStatus400() (*http.Response, error) {
	io, _ := os.Open("test_files/test_user.json")
	resp := http.Response{
		StatusCode: 400,
		Body:       io,
	}
	return &resp, nil
}

func MockHTTPResponseCertGood() (*http.Response, error) {
	obj := Registration{
		OrgID: "54321",
	}

	data, err := json.Marshal(obj)

	if err != nil {
		return nil, err
	}

	resp := http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBufferString(string(data))),
	}
	return &resp, nil
}

func MockHTTPResponseCertNotGood() (*http.Response, error) {
	resp := http.Response{
		StatusCode: http.StatusForbidden,
	}
	return &resp, nil
}

func TestNewCRCAuthValidatorEmptyBopURLInvalidPEM(t *testing.T) {
	conf := ValidatorConfig{
		BOPUrl: "",
	}

	os.Setenv("JWTPEM", "sup")

	validator, err := NewCRCAuthValidator(&conf)
	assert.Nil(t, err)

	err = validator.grabVerify()
	assert.NotNil(t, err)
}

func TestNewCRCAuthValidatorEmptyBopURLValidPEM(t *testing.T) {
	conf := ValidatorConfig{
		BOPUrl: "",
	}

	keyData, _ := os.ReadFile("test_files/public.pem")

	os.Setenv("JWTPEM", string(keyData))

	_, err := NewCRCAuthValidator(&conf)

	assert.Nil(t, err)

}

func TestNewCRCAuthValidatorBopURLCantGetKey(t *testing.T) {
	conf := ValidatorConfig{
		BOPUrl: "jomo",
	}

	deps.HTTP = &MockHTTP{}

	validator, err := NewCRCAuthValidator(&conf)
	assert.Nil(t, err)

	err = validator.grabVerify()

	assert.NotNil(t, err)

}

func TestNewCRCAuthValidatorBopURLCanGetKey(t *testing.T) {
	conf := ValidatorConfig{
		BOPUrl: "jomo",
	}

	deps.HTTP = &MockHTTP{
		logic: HTTPBodyIsKey,
	}

	keyData, _ := os.ReadFile("test_files/public.pem")
	key := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", string(keyData))

	validator, err := NewCRCAuthValidator(&conf)
	validator.grabVerify()

	assert.Nil(t, err)
	assert.Equal(t, key, validator.pem)

}

func TestProcessRequestBasicAuthOK(t *testing.T) {
	deps.HTTP = &MockHTTP{
		logic: MockHTTPResponseIsUserJSON,
	}

	req, _ := http.NewRequest("GET", "", nil)
	req.SetBasicAuth(testUser.Username, testUser.Password)

	c, errOne := NewCRCAuthValidator(&ValidatorConfig{})

	ident, errTwo := c.ProcessRequest(req)

	assert.Nil(t, errOne)
	assert.Nil(t, errTwo)

	assert.Equal(t, "billy", ident.Identity.User.Username)
	assert.Equal(t, "basic-auth", ident.Identity.AuthType)
	assert.Equal(t, "5432", ident.Identity.OrgID)
}

func TestProcessRequestBasicAuthNotOK(t *testing.T) {
	deps.HTTP = &MockHTTP{
		logic: MockHTTPResponseIsStatus400,
	}

	req, _ := http.NewRequest("GET", "", nil)
	req.SetBasicAuth(testUser.Username, testUser.Password)

	c, errOne := NewCRCAuthValidator(&ValidatorConfig{})

	ident, errTwo := c.ProcessRequest(req)

	assert.Nil(t, errOne)
	assert.NotNil(t, errTwo)
	assert.Nil(t, ident)
}

func TestProcessRequestBadAuthType(t *testing.T) {
	deps.HTTP = &MockHTTP{
		logic: MockHTTPResponseIsStatus400,
	}

	req, _ := http.NewRequest("GET", "", nil)

	c, errOne := NewCRCAuthValidator(&ValidatorConfig{})

	ident, errTwo := c.ProcessRequest(req)

	assert.Nil(t, errOne)
	assert.NotNil(t, errTwo)
	assert.Nil(t, ident)
}

func TestProcessRequestBearerAuthJWTInvalid(t *testing.T) {
	deps.HTTP = &MockHTTP{
		logic: MockHTTPResponseIsStatus400,
	}

	req, _ := http.NewRequest("GET", "", nil)
	req.Header.Set("Authorization", "Bearer")

	c, errOne := NewCRCAuthValidator(&ValidatorConfig{})

	ident, errTwo := c.ProcessRequest(req)

	assert.Nil(t, errOne)
	assert.NotNil(t, errTwo)
	assert.Nil(t, ident)
}

func TestProcessRequestBearerAuthJWTValid(t *testing.T) {
	jwtData, _ := os.ReadFile("test_files/jwt.txt")
	jwt := string(jwtData)

	keyData, _ := os.ReadFile("test_files/public.pem")

	os.Setenv("JWTPEM", string(keyData))

	req, _ := http.NewRequest("GET", "", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)

	c, errOne := NewCRCAuthValidator(&ValidatorConfig{})

	ident, errTwo := c.ProcessRequest(req)

	assert.Nil(t, errOne)
	assert.Nil(t, errTwo)
	assert.NotNil(t, ident)

	assert.Equal(t, "User", ident.Identity.Type)
	assert.Equal(t, "jwt-auth", ident.Identity.AuthType)
	assert.NotEqual(t, "ServiceAccount", ident.Identity.Type)
}

func TestServiceAccountJWTValid(t *testing.T) {

	xrhid := identity.XRHID{
		Identity: identity.Identity{
			AccountNumber:         "12345",
			EmployeeAccountNumber: "12345",
			OrgID:                 "54321",
			Internal: identity.Internal{
				OrgID:       "12345",
				AuthTime:    0,
				CrossAccess: false,
			},
			User: &identity.User{
				Username:  "jdoe",
				Email:     "",
				FirstName: "",
				LastName:  "",
				Active:    false,
				OrgAdmin:  false,
				Internal:  false,
				Locale:    "",
				UserID:    "",
			},
			System:    &identity.System{},
			Associate: &identity.Associate{},
			X509:      &identity.X509{},
			Type:      "ServiceAccount",
			AuthType:  "jwt-auth",
		},
		Entitlements: map[string]identity.ServiceDetails{"something": {
			IsEntitled: true,
			IsTrial:    true,
		}},
	}

	tokenString, err := CreateJWT(&xrhid)
	assert.NoError(t, err)
	assert.NotNil(t, tokenString)

	keyData, _ := os.ReadFile("test_files/public.pem")

	os.Setenv("JWTPEM", string(keyData))

	req, _ := http.NewRequest("GET", "", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	c, errOne := NewCRCAuthValidator(&ValidatorConfig{})

	ident, errTwo := c.ProcessRequest(req)

	assert.Nil(t, errOne)
	assert.Nil(t, errTwo)
	assert.NotNil(t, ident)
	assert.Equal(t, xrhid.Identity.Internal.OrgID, ident.Identity.Internal.OrgID)
	assert.Equal(t, "ServiceAccount", ident.Identity.Type)
}

func TestProcessCookieAuthJWTValid(t *testing.T) {
	deps.HTTP = &MockHTTP{
		logic: MockHTTPResponseIsStatus400,
	}

	jwtData, _ := os.ReadFile("test_files/jwt.txt")
	jwt := string(jwtData)

	keyData, _ := os.ReadFile("test_files/public.pem")

	os.Setenv("JWTPEM", string(keyData))

	oreo := http.Cookie{}
	oreo.Name = "cs_jwt"
	oreo.Value = jwt

	req, _ := http.NewRequest("GET", "", nil)
	req.AddCookie(&oreo)

	c, errOne := NewCRCAuthValidator(&ValidatorConfig{})

	ident, errTwo := c.ProcessRequest(req)

	assert.Nil(t, errOne)
	assert.Nil(t, errTwo)
	assert.NotNil(t, ident)
}

func TestProcessRequestCertAuthOK(t *testing.T) {
	deps.HTTP = &MockHTTP{
		logic: MockHTTPResponseCertGood,
	}

	req, _ := http.NewRequest("GET", "", nil)
	req.Header.Add("x-rh-check-reg", "boop")
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{
			Subject: pkix.Name{
				Organization: []string{"orgBoop"},
				CommonName:   "cnBoop",
			},
		}},
	}

	c, errOne := NewCRCAuthValidator(&ValidatorConfig{})

	ident, errTwo := c.ProcessRequest(req)

	assert.Nil(t, errOne)
	assert.Nil(t, errTwo)
	assert.Equal(t, "cnBoop", ident.Identity.System.CommonName)
	assert.Equal(t, "54321", ident.Identity.OrgID)
	assert.Equal(t, "54321", ident.Identity.Internal.OrgID)
}

func TestProcessRequestCertAuthNotOK(t *testing.T) {
	deps.HTTP = &MockHTTP{
		logic: MockHTTPResponseCertNotGood,
	}

	req, _ := http.NewRequest("GET", "", nil)
	req.Header.Add("x-rh-check-reg", "boop")
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{
			Subject: pkix.Name{
				Organization: []string{"orgBoop"},
				CommonName:   "cnBoop",
			},
		}},
	}

	c, errOne := NewCRCAuthValidator(&ValidatorConfig{})

	ident, errTwo := c.ProcessRequest(req)

	assert.Nil(t, errOne)
	assert.NotNil(t, errTwo)
	assert.Nil(t, ident)
}
