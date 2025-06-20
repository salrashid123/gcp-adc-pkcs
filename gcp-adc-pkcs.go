package gcppkcscredential

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	pk "github.com/salrashid123/golang-jwt-pkcs11"
	pkcs11uri "github.com/stefanberger/go-pkcs11uri"
	"golang.org/x/oauth2"
)

type oauthJWT struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

type Token struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

var ()

const ()

type GCPPKCSConfig struct {
	PKCSURI string

	ExpireIn int

	IdentityToken       bool
	Audience            string
	ServiceAccountEmail string
	Scopes              []string
}

var ()

func NewGCPPKCSCredential(cfg *GCPPKCSConfig) (Token, error) {

	uri := pkcs11uri.New()

	err := uri.Parse(cfg.PKCSURI)
	if err != nil {

		return Token{}, fmt.Errorf("gcp-adc-pkcs: Error parsing pkcs11 URI %v", err)
	}

	//uri.SetAllowedModulePaths([]string{"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"})
	uri.SetAllowAnyModule(true)
	module, err := uri.GetModule()
	if err != nil {
		return Token{}, fmt.Errorf("gcp-adc-pkcs: loading module from path %v", err)
	}

	pin, err := uri.GetPIN()
	if err != nil {
		return Token{}, fmt.Errorf("gcp-adc-pkcs: extracting PIN from URI %v", err)
	}

	config := &pk.PKConfig{
		Pin:  pin,
		Path: module,
	}

	cntr := 0
	var slotid int
	slot, ok := uri.GetPathAttribute("slot-id", false)
	if ok {
		cntr++
		slotid, err = strconv.Atoi(slot)
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-pkcs converting slot to string %v", err)
		}
		config.SlotNumber = &slotid
	}
	tokenlabel, ok := uri.GetPathAttribute("token", false)
	if ok {
		cntr++
		config.TokenLabel = tokenlabel
	}
	serial, ok := uri.GetPathAttribute("serial", false)
	if ok {
		cntr++
		config.TokenSerial = serial
	}

	if cntr > 1 {
		return Token{}, fmt.Errorf("gcp-adc-pkcs: exactly one of tokenlabel or slot-id or serial must be specified")
	}

	id, ok := uri.GetPathAttribute("id", false)
	if !ok {
		return Token{}, fmt.Errorf("gcp-adc-pkcs: loading PKCS ID from URI %s", cfg.PKCSURI)
	}

	pkcs_object_id, err := hex.DecodeString(id)
	if err != nil {
		return Token{}, fmt.Errorf("gcp-adc-pkcs:  converting hex id to string %v", err)
	}
	config.PKCS_ID = pkcs_object_id

	object, ok := uri.GetPathAttribute("object", false)
	if !ok {
		return Token{}, fmt.Errorf("gcp-adc-pkcs: Error no object in URI %s", cfg.PKCSURI)
	}
	config.KeyID = object

	// now we're ready to sign

	if cfg.IdentityToken {
		if cfg.Audience == "" {
			return Token{}, fmt.Errorf("gcp-adc-pkcs:   audience must be set if --identityToken is used")
		}
		iat := time.Now()
		exp := iat.Add(time.Second * 10)

		type idTokenJWT struct {
			jwt.RegisteredClaims
			TargetAudience string `json:"target_audience"`
		}

		claims := &idTokenJWT{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    cfg.ServiceAccountEmail,
				IssuedAt:  jwt.NewNumericDate(iat),
				ExpiresAt: jwt.NewNumericDate(exp),
				Audience:  []string{"https://oauth2.googleapis.com/token"},
			},
			TargetAudience: cfg.Audience,
		}

		pk.SigningMethodPKRS256.Override()
		jwt.MarshalSingleStringAsArray = false
		token := jwt.NewWithClaims(pk.SigningMethodPKRS256, claims)

		ctx := context.Background()

		keyctx, err := pk.NewPKContext(ctx, config)
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-pkcs: Unable to initialize : %v", err)
		}

		tokenString, err := token.SignedString(keyctx)
		if err != nil {
			fmt.Printf("Error signing %v", err)
			os.Exit(1)
		}
		client := &http.Client{}

		data := url.Values{}
		data.Add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
		data.Add("assertion", tokenString)

		hreq, err := http.NewRequest(http.MethodPost, "https://oauth2.googleapis.com/token", bytes.NewBufferString(data.Encode()))
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-pkcs: Error: Unable to generate token Request, %v", err)
		}
		hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
		resp, err := client.Do(hreq)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: unable to POST token request, %v\n", err)
		}

		if resp.StatusCode != http.StatusOK {
			f, err := io.ReadAll(resp.Body)
			if err != nil {
				return Token{}, fmt.Errorf("gcp-adc-pkcs: Error Reading response body, %v", err)
			}
			return Token{}, fmt.Errorf("gcp-adc-pkcs: Error: Token Request error:, %s", f)
		}
		defer resp.Body.Close()

		type idTokenResponse struct {
			IdToken string `json:"id_token"`
		}

		var ret idTokenResponse
		err = json.NewDecoder(resp.Body).Decode(&ret)
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-pkcs: Error: decoding token:, %s", err)
		}
		idTokenSource := oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: ret.IdToken,
		})
		t, err := idTokenSource.Token()
		if err != nil {
			return Token{}, fmt.Errorf("gcp-adc-pkcs: Error: decoding token:, %s", err)
		}
		return Token{
			AccessToken: t.AccessToken,
		}, nil

	}
	iat := time.Now()
	exp := iat.Add(time.Hour)

	claims := &oauthJWT{
		Scope: strings.Join(cfg.Scopes, " "),
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(iat),
			ExpiresAt: jwt.NewNumericDate(exp),
			Issuer:    cfg.ServiceAccountEmail,
			Subject:   cfg.ServiceAccountEmail,
		},
	}

	pk.SigningMethodPKRS256.Override()
	jwt.MarshalSingleStringAsArray = false
	token := jwt.NewWithClaims(pk.SigningMethodPKRS256, claims)

	ctx := context.Background()

	keyctx, err := pk.NewPKContext(ctx, config)
	if err != nil {
		return Token{}, fmt.Errorf("gcp-adc-pkcs: Unable to initialize context: %v", err)
	}

	tokenString, err := token.SignedString(keyctx)
	if err != nil {
		return Token{}, fmt.Errorf("gcp-adc-pkcs: Error signing %v", err)
	}

	f := &oauth2.Token{AccessToken: tokenString, TokenType: "Bearer", Expiry: exp}

	return Token{
		AccessToken: f.AccessToken,
		TokenType:   f.TokenType,
		ExpiresIn:   int64(exp.Sub(iat).Seconds()),
	}, nil
}
