package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	pk "github.com/salrashid123/golang-jwt-pkcs11"
	pkcs11uri "github.com/stefanberger/go-pkcs11uri"
)

type oauthJWT struct {
	jwt.RegisteredClaims
	Scope string `json:"scope"`
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

	// now sign the data
	iat := time.Now()
	exp := iat.Add(time.Hour)

	claims := &oauthJWT{
		jwt.RegisteredClaims{
			Issuer:    *svcAccountEmail,
			Audience:  []string{"https://oauth2.googleapis.com/token"},
			IssuedAt:  jwt.NewNumericDate(iat),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		"https://www.googleapis.com/auth/cloud-platform",
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
	data.Set("grant_type", "assertion")
	data.Add("assertion_type", "http://oauth.net/grant_type/jwt/1.0/bearer")
	data.Add("assertion", tokenString)

	hreq, err := http.NewRequest("POST", "https://oauth2.googleapis.com/token", bytes.NewBufferString(data.Encode()))
	if err != nil {
		fmt.Printf("Error: Unable to generate token Request, %v\n", err)
		os.Exit(1)
	}
	hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	resp, err := client.Do(hreq)
	if err != nil {
		fmt.Printf("Error: unable to POST token request, %v\n", err)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Error: Token Request error:, %v\n", err)
		f, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("Error Reading response body, %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Error response from oauth2 %s\n", f)
		os.Exit(1)
	}

	f, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error: unable to parse token response, %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	fmt.Println(string(f))
}
