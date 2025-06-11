package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
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

type rtokenJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

var (
	pkcsURI         = flag.String("pkcsURI", "", "Full PKCSURI")
	svcAccountEmail = flag.String("serviceAccountEmail", "", "Service Account Email")
	scopes          = flag.String("scopes", "https://www.googleapis.com/auth/cloud-platform", "comma separated scopes")
	identityToken   = flag.Bool("identityToken", false, "Generate google ID token (default: false)")
	audience        = flag.String("audience", "", "Audience for the OIDC token")
)

const ()

func main() {

	flag.Parse()

	if *pkcsURI == "" || *svcAccountEmail == "" {
		fmt.Println("Both pkcsURI and serviceAccountEmail must be specified")
		os.Exit(1)
	}

	uri := pkcs11uri.New()

	err := uri.Parse(*pkcsURI)
	if err != nil {
		fmt.Printf("Error parsing pkcs11 URI %v\n", err)
		os.Exit(1)
	}

	//uri.SetAllowedModulePaths([]string{"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"})
	uri.SetAllowAnyModule(true)
	module, err := uri.GetModule()
	if err != nil {
		fmt.Printf("Error loading module from path %v\n", err)
		os.Exit(1)
	}

	pin, err := uri.GetPIN()
	if err != nil {
		fmt.Printf("Error extracting PIN from URI %v\n", err)
		os.Exit(1)
	}

	slot, ok := uri.GetPathAttribute("slot-id", false)
	if !ok {
		fmt.Printf("Error reading slot-id PIN from URI %s\n", *pkcsURI)
		os.Exit(1)
	}
	slotid, err := strconv.Atoi(slot)
	if err != nil {
		fmt.Printf("Error converting slot to string %v\n", err)
		os.Exit(1)
	}

	id, ok := uri.GetPathAttribute("id", false)
	if !ok {
		fmt.Printf("Error loading PKCS ID from URI %s\n", *pkcsURI)
		os.Exit(1)
	}

	hex_id, err := hex.DecodeString(id)
	if err != nil {
		fmt.Printf("Error converting hex id to string %v\n", err)
		os.Exit(1)
	}

	object, ok := uri.GetPathAttribute("object", false)
	if !ok {
		fmt.Printf("Error no object in URI %s\n", *pkcsURI)
		os.Exit(1)
	}

	config := &pk.PKConfig{
		Pin:        pin,
		KeyLabel:   object,
		PKCS_ID:    hex_id,
		SlotNumber: &slotid,
		Path:       module,
	}

	// now we're ready to sign

	if *identityToken {
		if *audience == "" {
			fmt.Fprintf(os.Stderr, "ERROR:  audience must be set if --identityToken is used")
			return
		}
		iat := time.Now()
		exp := iat.Add(time.Second * 10)

		type idTokenJWT struct {
			jwt.RegisteredClaims
			TargetAudience string `json:"target_audience"`
		}

		claims := &idTokenJWT{
			jwt.RegisteredClaims{
				Issuer:    *svcAccountEmail,
				IssuedAt:  jwt.NewNumericDate(iat),
				ExpiresAt: jwt.NewNumericDate(exp),
				Audience:  []string{"https://oauth2.googleapis.com/token"},
			},
			*audience,
		}

		pk.SigningMethodPKRS256.Override()
		jwt.MarshalSingleStringAsArray = false
		token := jwt.NewWithClaims(pk.SigningMethodPKRS256, claims)

		ctx := context.Background()

		keyctx, err := pk.NewPKContext(ctx, config)
		if err != nil {
			fmt.Printf("Unable to initialize tpmJWT: %v", err)
			os.Exit(1)
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
			fmt.Fprintf(os.Stderr, "Error: Unable to generate token Request, %v\n", err)
			return
		}
		hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
		resp, err := client.Do(hreq)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: unable to POST token request, %v\n", err)
			return
		}

		if resp.StatusCode != http.StatusOK {
			f, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error Reading response body, %v\n", err)
				return
			}
			fmt.Fprintf(os.Stderr, "Error: Token Request error:, %s\n", f)
			return
		}
		defer resp.Body.Close()

		type idTokenResponse struct {
			IdToken string `json:"id_token"`
		}

		var ret idTokenResponse
		err = json.NewDecoder(resp.Body).Decode(&ret)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: decoding token:, %s\n", err)
			return
		}
		idTokenSource := oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: ret.IdToken,
		})
		t, err := idTokenSource.Token()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: decoding token:, %s\n", err)
			return
		}
		fmt.Println(string(t.AccessToken))
		return

	}
	iat := time.Now()
	exp := iat.Add(time.Hour)

	claims := &oauthJWT{
		Scope: strings.Replace(*scopes, ",", " ", -1),
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(iat),
			ExpiresAt: jwt.NewNumericDate(exp),
			Issuer:    *svcAccountEmail,
			Subject:   *svcAccountEmail,
		},
	}

	pk.SigningMethodPKRS256.Override()
	jwt.MarshalSingleStringAsArray = false
	token := jwt.NewWithClaims(pk.SigningMethodPKRS256, claims)

	ctx := context.Background()

	keyctx, err := pk.NewPKContext(ctx, config)
	if err != nil {
		fmt.Printf("Unable to initialize tpmJWT: %v", err)
		os.Exit(1)
	}

	tokenString, err := token.SignedString(keyctx)
	if err != nil {
		fmt.Printf("Error signing %v", err)
		os.Exit(1)
	}

	f := &oauth2.Token{AccessToken: tokenString, TokenType: "Bearer", Expiry: exp}

	fs, err := json.Marshal(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating json sting %v", err)
		os.Exit(1)
	}
	fmt.Println(string(fs))
}
