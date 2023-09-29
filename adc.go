package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/miekg/pkcs11"
	pkcs11uri "github.com/stefanberger/go-pkcs11uri"
	"golang.org/x/oauth2/jws"
)

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

	p := pkcs11.New(module)
	err = p.Initialize()
	if err != nil {
		fmt.Printf("Error initializing pkcs  %v\n", err)
		os.Exit(1)
	}

	defer p.Destroy()
	defer p.Finalize()

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

	session, err := p.OpenSession(uint(slotid), pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		fmt.Printf("Error opening session %v\n", err)
		os.Exit(1)
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		fmt.Printf("Error logging in %v\n", err)
		os.Exit(1)
	}
	defer p.Logout(session)

	/// *************************** Sign

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, object),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, hex_id),
	}

	if err := p.FindObjectsInit(session, privateKeyTemplate); err != nil {
		fmt.Printf("Error finding PKCS ObjectInit %v\n", err)
		os.Exit(1)
	}
	pk, _, err := p.FindObjects(session, 1)
	if err != nil {
		fmt.Printf("Error finding object %v\n", err)
		os.Exit(1)
	}
	if len(pk) == 0 {
		fmt.Printf("Error finding private key \n")
		os.Exit(1)
	}
	if err = p.FindObjectsFinal(session); err != nil {
		fmt.Printf("Error finalizing session %v\n", err)
		os.Exit(1)
	}

	err = p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)}, pk[0])
	if err != nil {
		fmt.Printf("Error signing init %v\n", err)
		os.Exit(1)
	}

	// now we're ready to sign

	iat := time.Now()
	exp := iat.Add(time.Hour)

	hdr, err := json.Marshal(&jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
	})
	if err != nil {
		fmt.Printf("google: Unable to marshal  JWT Header: %v", err)
		os.Exit(1)
	}
	cs, err := json.Marshal(&jws.ClaimSet{
		Iss:   *svcAccountEmail,
		Scope: "https://www.googleapis.com/auth/cloud-platform",
		Aud:   "https://accounts.google.com/o/oauth2/token",
		Iat:   iat.Unix(),
		Exp:   exp.Unix(),
	})
	if err != nil {
		fmt.Printf("google: Unable to marshal  JWT ClaimSet: %v\n", err)
		os.Exit(1)
	}

	j := base64.URLEncoding.EncodeToString([]byte(hdr)) + "." + base64.URLEncoding.EncodeToString([]byte(cs))

	// now sign the data

	sig, err := p.Sign(session, []byte(j))
	if err != nil {
		fmt.Printf("Error signing %v\n", err)
		os.Exit(1)
	}
	r := j + "." + base64.RawURLEncoding.EncodeToString(sig)

	client := &http.Client{}

	data := url.Values{}
	data.Set("grant_type", "assertion")
	data.Add("assertion_type", "http://oauth.net/grant_type/jwt/1.0/bearer")
	data.Add("assertion", r)

	hreq, err := http.NewRequest("POST", "https://accounts.google.com/o/oauth2/token", bytes.NewBufferString(data.Encode()))
	hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	if err != nil {
		fmt.Printf("Error: Unable to generate token Request, %v\n", err)
		os.Exit(1)
	}
	resp, err := client.Do(hreq)
	if err != nil {
		fmt.Printf("Error: unable to POST token request, %v\n", err)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("salrashid123/x/oauth2/google: Token Request error:, %v\n", err)
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
	resp.Body.Close()
	// var m rtokenJSON
	// err = json.Unmarshal(f, &m)
	// if err != nil {
	// 	fmt.Printf("Error: Unable to unmarshal response, %v", err)
	// 	os.Exit(0)
	// }

	// b, err := json.Marshal(user)
	// if err != nil {
	//     fmt.Println(err)
	//     return
	// }
	fmt.Println(string(f))

}
