package crcauthlib

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/golang-jwt/jwt/v4/request"
	"github.com/redhatinsights/crcauthlib/deps"
	identity "github.com/redhatinsights/platform-go-middlewares/v2/identity"
)

type Registration struct {
	ID          string
	OrgID       string
	Username    string
	UID         string
	DisplayName string
	Extra       map[string]interface{}
	CreatedAt   time.Time
}

type User struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	ID            int    `json:"id"`
	Email         string `json:"email"`
	FirstName     string `json:"first_name"`
	LastName      string `json:"last_name"`
	AccountNumber string `json:"account_number"`
	AddressString string `json:"address_string"`
	IsActive      bool   `json:"is_active"`
	IsOrgAdmin    bool   `json:"is_org_admin"`
	IsInternal    bool   `json:"is_internal"`
	Locale        string `json:"locale"`
	OrgID         string `json:"org_id"`
	DisplayName   string `json:"display_name"`
	Type          string `json:"type"`
	Entitlements  string `json:"entitlements"`
}

type Resp struct {
	User      User   `json:"user"`
	Mechanism string `json:"mechanism"`
}

type Entitlement struct {
	IsTrial    bool `json:"is_trial"`
	IsEntitled bool `json:"is_entitled"`
}

type XRHID struct {
	Identity     identity.Identity      `json:"identity,omitempty"`
	Entitlements map[string]Entitlement `json:"entitlements,omitempty"`
}

type CRCAuthValidator struct {
	config    *ValidatorConfig
	pem       string
	verifyKey *rsa.PublicKey
}

type ValidatorConfig struct {
	BOPUrl string `json:"bopurl,omitempty"`
}

func NewCRCAuthValidator(config *ValidatorConfig) (*CRCAuthValidator, error) {
	validator := &CRCAuthValidator{config: config}
	return validator, nil
}

func (crc *CRCAuthValidator) ProcessRequest(r *http.Request) (*identity.XRHID, error) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		fmt.Println("incoming request: processing with cert auth")
		return crc.processCert(r.TLS.PeerCertificates[0])
	} else if user, pass, ok := r.BasicAuth(); ok {
		fmt.Println("incoming request: processing with basic authentication")
		return crc.processBasicAuth(user, pass)
	} else if strings.Contains(r.Header.Get("Authorization"), "Bearer") {
		fmt.Println("incoming request: processing bearer auth header")
		return crc.processJWTHeaderRequest(r)
	} else if _, err := r.Cookie("cs_jwt"); err == nil {
		fmt.Println("incoming request: processing cs_jwt cookie")
		return crc.processJWTCookieRequest(r)
	} else {
		fmt.Println("incoming request: unable to determine auth type")
		return nil, fmt.Errorf("bad auth type")
	}
}

func (crc *CRCAuthValidator) ProcessToken(tokenString string) (*identity.XRHID, error) {
	identity, err := crc.processJWTToken(tokenString)

	if err != nil {
		return nil, err
	}
	return identity, nil
}

func (crc *CRCAuthValidator) grabVerify() error {
	if crc.config.BOPUrl != "" {
		resp, err := deps.HTTP.Get(fmt.Sprintf("%s/v1/jwt", crc.config.BOPUrl))
		if err != nil {
			return fmt.Errorf("could not obtain key: %s", err.Error())
		}
		key, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("could not read key body: %s", err.Error())
		}
		crc.pem = fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", key)
		fmt.Printf("PEM Read Successfully\n")
	} else {
		crc.pem = os.Getenv("JWTPEM")
	}
	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(crc.pem))
	if err != nil {
		fmt.Println("couldn't verify cert" + err.Error())
		return err
	} else {
		crc.verifyKey = verifyKey
		fmt.Printf("PEM Verified Successfully\n")
	}
	return nil
}

func (crc *CRCAuthValidator) ValidateJWTToken(tokenString string) (*jwt.Token, error) {
	if crc.verifyKey == nil {
		if err := crc.grabVerify(); err != nil {
			return nil, err
		}
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			fmt.Println("unexpected signing method")
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return crc.verifyKey, nil
	})

	if err != nil {
		fmt.Println("couldn't validate jwt tokenstring", err.Error())
		return nil, err
	}

	return token, nil
}

func (crc *CRCAuthValidator) ValidateJWTCookieRequest(r *http.Request) (*jwt.Token, error) {
	if crc.verifyKey == nil {
		if err := crc.grabVerify(); err != nil {
			return nil, err
		}
	}

	jwtToken, err := r.Cookie("cs_jwt")

	if err != nil {
		return nil, err
	}

	token, err := crc.ValidateJWTToken(jwtToken.Value)

	if err != nil {
		fmt.Println("couldn't validate jwt cookie", err.Error())
		return nil, err
	}

	return token, nil
}

func (crc *CRCAuthValidator) ValidateJWTHeaderRequest(r *http.Request) (*jwt.Token, error) {
	if crc.verifyKey == nil {
		if err := crc.grabVerify(); err != nil {
			return nil, fmt.Errorf("couldn't get public key: %w", err)
		}
	}
	token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			fmt.Println("unexpected signing method")
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return crc.verifyKey, nil
	})

	if err != nil {
		fmt.Println("couldn't validate jwt header", err.Error())
		return nil, fmt.Errorf("couldn't validate jwt header: %w", err)
	}

	return token, nil
}

// Private Methods
func (crc *CRCAuthValidator) processCert(cert *x509.Certificate) (*identity.XRHID, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/check_registration", crc.config.BOPUrl), nil)
	if err != nil {
		return nil, fmt.Errorf("could not prep request :%w", err)
	}

	req.Header.Add("x-rh-check-reg", cert.Subject.CommonName)

	resp, err := deps.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach reg endpoint :%w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("system CN not recognised")
	}

	dta, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, fmt.Errorf("could not extract registration information")
	}

	resp.Body.Close()

	obj := &Registration{}
	err = json.Unmarshal(dta, obj)

	if err != nil {
		return nil, fmt.Errorf("could not unmarshal registration information")
	}

	entitlements := map[string]identity.ServiceDetails{}

	ident := &identity.XRHID{
		Identity: identity.Identity{
			OrgID: obj.OrgID,
			Internal: identity.Internal{
				OrgID: obj.OrgID,
			},
			System: &identity.System{
				CommonName: cert.Subject.CommonName,
				CertType:   "system",
			},
			AuthType: "cert-auth",
			Type:     "System",
		},
		Entitlements: entitlements,
	}

	return ident, nil
}

func (crc *CRCAuthValidator) processBasicAuth(user string, password string) (*identity.XRHID, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/auth", crc.config.BOPUrl), nil)
	req.SetBasicAuth(user, password)
	if err != nil {
		return nil, fmt.Errorf("could not create request: %s", err.Error())
	}

	resp, err := deps.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bad request: %s", err.Error())
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("bad request: %s", err.Error())
	}
	respData := &Resp{}
	if resp.StatusCode == 200 {
		err := json.Unmarshal(data, respData)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling json: %s", err.Error())
		}

		entitlements := map[string]identity.ServiceDetails{}

		if respData.User.Entitlements != "" {
			err := json.Unmarshal([]byte(respData.User.Entitlements), &entitlements)
			if err != nil {
				return nil, err
			}
		}

		ident := &identity.XRHID{
			Identity: identity.Identity{
				AccountNumber: respData.User.AccountNumber,
				OrgID:         respData.User.OrgID,
				Internal: identity.Internal{
					OrgID: respData.User.OrgID,
				},
				User: &identity.User{
					Username:  respData.User.Username,
					Email:     respData.User.Email,
					FirstName: respData.User.FirstName,
					LastName:  respData.User.LastName,
					Active:    respData.User.IsActive,
					OrgAdmin:  respData.User.IsOrgAdmin,
					Internal:  respData.User.IsInternal,
					Locale:    respData.User.Locale,
				},
				AuthType: "basic-auth",
				Type:     respData.User.Type,
			},
			Entitlements: entitlements,
		}
		return ident, nil
	} else {
		return nil, fmt.Errorf("could not verify credentials")
	}
}

func (crc *CRCAuthValidator) processJWTCookieRequest(r *http.Request) (*identity.XRHID, error) {
	token, err := crc.ValidateJWTCookieRequest(r)

	if err != nil {
		return nil, err
	}

	return crc.buildIdent(token)
}

func (crc *CRCAuthValidator) processJWTHeaderRequest(r *http.Request) (*identity.XRHID, error) {
	token, err := crc.ValidateJWTHeaderRequest(r)

	if err != nil {
		return nil, err
	}

	return crc.buildIdent(token)
}

func (crc *CRCAuthValidator) processJWTToken(tokenString string) (*identity.XRHID, error) {
	token, err := crc.ValidateJWTToken(tokenString)

	if err != nil {
		return nil, err
	}

	return crc.buildIdent(token)
}

func getStringClaim(claimName string, claims jwt.MapClaims) string {
	claim, ok := claims[claimName].(string)
	if !ok {
		return "unknown"
	}
	return claim
}

func getBoolClaim(claimName string, claims jwt.MapClaims) bool {
	claim, ok := claims[claimName].(bool)
	if !ok {
		return false
	}
	return claim
}

func getArrayString(claimName string, claims jwt.MapClaims) []string {
	listEntitle := []string{}
	v, ok := claims[claimName].([]interface{})
	if !ok {
		return nil
	}

	if len(v) == 0 {
		return nil
	}

	for _, t := range v {
		r, ok := t.(string)
		if !ok {
			return nil
		}
		listEntitle = append(listEntitle, r)
	}

	return listEntitle
}

func (crc *CRCAuthValidator) buildIdent(token *jwt.Token) (*identity.XRHID, error) {
	var ident identity.XRHID
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {

		entitlements := map[string]identity.ServiceDetails{}

		if getArrayString("newEntitlements", claims) != nil {
			entitlementString := fmt.Sprintf("{%s}", strings.Join(getArrayString("newEntitlements", claims), ","))
			err := json.Unmarshal([]byte(entitlementString), &entitlements)
			if err != nil {
				return nil, fmt.Errorf("couldn't extract newEntitlements: %w", err)
			}
		} else {
			entitlementString := getStringClaim("entitlements", claims)
			if entitlementString != "" {
				err := json.Unmarshal([]byte(entitlementString), &entitlements)
				if err != nil {
					return nil, fmt.Errorf("couldn't extract old Entitlements: %w", err)
				}
			}
		}

		if getStringClaim("service_account", claims) != "true" {
			ident = identity.XRHID{
				Identity: identity.Identity{
					OrgID:         getStringClaim("org_id", claims),
					AccountNumber: getStringClaim("account_number", claims),
					Internal: identity.Internal{
						OrgID: getStringClaim("org_id", claims),
					},
					User: &identity.User{
						Username:  getStringClaim("username", claims),
						Email:     getStringClaim("email", claims),
						FirstName: getStringClaim("first_name", claims),
						LastName:  getStringClaim("last_name", claims),
						Active:    getBoolClaim("is_active", claims),
						OrgAdmin:  getBoolClaim("is_org_admin", claims),
						Internal:  getBoolClaim("is_internal", claims),
						Locale:    getStringClaim("org_id", claims),
					},
					AuthType: "jwt-auth",
					Type:     "User",
				},
				Entitlements: entitlements,
			}
		} else {
			ident = identity.XRHID{
				Identity: identity.Identity{
					OrgID: getStringClaim("org_id", claims),
					Internal: identity.Internal{
						OrgID: getStringClaim("org_id", claims),
					},
					AuthType: "jwt-auth",
					Type:     "ServiceAccount",
					ServiceAccount: &identity.ServiceAccount{
						Username: fmt.Sprintf("service-account-%s", getStringClaim("client_id", claims)),
						ClientId: getStringClaim("client_id", claims),
					},
				},
				Entitlements: entitlements,
			}
		}
	}

	return &ident, nil
}
