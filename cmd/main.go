package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	gcppkcscredential "github.com/salrashid123/gcp-adc-pkcs"
)

const ()

var (
	pkcsURI         = flag.String("pkcsURI", "", "Full PKCSURI")
	svcAccountEmail = flag.String("serviceAccountEmail", "", "Service Account Email")
	scopes          = flag.String("scopes", "https://www.googleapis.com/auth/cloud-platform", "comma separated scopes")
	identityToken   = flag.Bool("identityToken", false, "Generate google ID token (default: false)")
	audience        = flag.String("audience", "", "Audience for the OIDC token")
	expireIn        = flag.Int("expireIn", 3600, "Token expires in seconds")

	version = flag.Bool("version", false, "print version")

	Commit, Tag, Date string
)

func main() {

	flag.Parse()

	if *version {
		// go build  -ldflags="-s -w -X main.Tag=$(git describe --tags --abbrev=0) -X main.Commit=$(git rev-parse HEAD)" cmd/main.go
		fmt.Printf("Version: %s\n", Tag)
		fmt.Printf("Date: %s\n", Date)
		fmt.Printf("Commit: %s\n", Commit)
		os.Exit(0)
	}

	if *pkcsURI == "" || *svcAccountEmail == "" {
		fmt.Println("Both pkcsURI and serviceAccountEmail must be specified")
		os.Exit(1)
	}

	resp, err := gcppkcscredential.NewGCPPKCSCredential(&gcppkcscredential.GCPPKCSConfig{

		PKCSURI:             *pkcsURI,
		IdentityToken:       *identityToken,
		Audience:            *audience,
		ServiceAccountEmail: *svcAccountEmail,
		ExpireIn:            *expireIn,
		Scopes:              strings.Split(*scopes, ","),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "gcp-pkcs-process-credential: Error getting credentials %v", err)
		os.Exit(1)
	}
	m, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gcp-pkcs-process-credential: Error marshalling processCredential output %v", err)
		os.Exit(1)
	}
	fmt.Println(string(m))
}
