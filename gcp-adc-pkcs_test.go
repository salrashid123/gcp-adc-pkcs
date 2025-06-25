package gcppkcscredential

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
)

const (
	newpin       = "mynewpin"
	defaultpin   = "1234"
	defaultLabel = "token1"
)

var (
	//lib = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
	lib = "/usr/lib/softhsm/libsofthsm2.so"
)

func loadKey(t *testing.T, privKeyPEM string) ([]byte, string, error) {

	tempDir := t.TempDir()
	tempFilePath := filepath.Join(tempDir, "softhsm.conf")

	softHSMConf := fmt.Sprintf(`\nlog.level = DEBUG
objectstore.backend = file
directories.tokendir = %s
slots.removable = true`, tempDir)

	// Write the content to the temporary file
	err := os.WriteFile(tempFilePath, []byte(softHSMConf), 0644)
	if err != nil {
		return nil, "", err
	}

	t.Setenv("SOFTHSM2_CONF", tempFilePath)

	p := pkcs11.New(lib)

	err = p.Initialize()
	if err != nil {
		return nil, "", err
	}

	defer p.Destroy()
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		return nil, "", err
	}
	// si, err := p.GetSlotInfo(0)
	// if err != nil {
	// 	return nil, "", err
	// }

	err = p.InitToken(0, defaultpin, defaultLabel)
	if err != nil {
		return nil, "", err
	}

	ssession, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, "", err
	}
	defer p.CloseSession(ssession)

	err = p.Login(ssession, pkcs11.CKU_SO, defaultpin)
	if err != nil {
		return nil, "", err
	}

	err = p.InitPIN(ssession, newpin)
	if err != nil {
		return nil, "", err
	}

	err = p.Logout(ssession)
	if err != nil {
		return nil, "", err
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, "", err
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, newpin)
	if err != nil {
		return nil, "", err
	}
	defer p.Logout(session)

	// info, err := p.GetInfo()
	// if err != nil {
	// 	return nil , "", err
	// }
	// t.Logf("CryptokiVersion.Major %v", info.CryptokiVersion.Major)

	privPem, _ := pem.Decode([]byte(privKeyPEM))
	if privPem == nil {
		return nil, "", fmt.Errorf("error parsing privatekeyPEM")
	}

	privateKeyi, err := x509.ParsePKCS8PrivateKey(privPem.Bytes)
	if err != nil {
		return nil, "", err
	}

	privateKey, ok := privateKeyi.(*rsa.PrivateKey)
	if !ok {
		return nil, "", fmt.Errorf("error converting privatekeyPEM")
	}

	c, err := p.GetTokenInfo(0)
	if err != nil {
		return nil, "", err
	}

	// first lookup the key
	buf := new(bytes.Buffer)
	var num uint16 = 1
	err = binary.Write(buf, binary.LittleEndian, num)
	if err != nil {
		return nil, "", err
	}
	pubID := buf.Bytes()

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, privateKey.PublicKey.N.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "pub1"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, pubID),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "priv1"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, pubID),

		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),

		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),

		pkcs11.NewAttribute(pkcs11.CKA_WRAP_WITH_TRUSTED, false),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),

		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, privateKey.PublicKey.N.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE_EXPONENT, big.NewInt(int64(privateKey.E)).Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIME_1, new(big.Int).Set(privateKey.Primes[0]).Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIME_2, new(big.Int).Set(privateKey.Primes[1]).Bytes()),

		pkcs11.NewAttribute(pkcs11.CKA_EXPONENT_1, new(big.Int).Set(privateKey.Precomputed.Dp).Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_EXPONENT_2, new(big.Int).Set(privateKey.Precomputed.Dq).Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_COEFFICIENT, new(big.Int).Set(privateKey.Precomputed.Qinv).Bytes()),
	}

	_, err = p.CreateObject(session, publicKeyTemplate)
	if err != nil {
		return nil, "", err
	}

	_, err = p.CreateObject(session, privateKeyTemplate)
	if err != nil {
		return nil, "", err
	}

	return pubID, c.SerialNumber, nil
}

func TestToken(t *testing.T) {

	saEmail := os.Getenv("CICD_SA_EMAIL")
	saPEM := os.Getenv("CICD_SA_PEM")

	keyID, serial, err := loadKey(t, saPEM)
	require.NoError(t, err)

	tests := []struct {
		name string
		url  string
	}{
		{"serial", fmt.Sprintf("pkcs11:model=SoftHSM%%20v2;manufacturer=SoftHSM%%20project;serial=%s;object=priv1;id=%s?pin-value=mynewpin&module-path=%s", serial, hex.EncodeToString(keyID), lib)},
		{"label", fmt.Sprintf("pkcs11:model=SoftHSM%%20v2;manufacturer=SoftHSM%%20project;token=token1;object=priv1;id=%s?pin-value=mynewpin&module-path=%s", hex.EncodeToString(keyID), lib)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewGCPPKCSCredential(&GCPPKCSConfig{
				PKCSURI:             tc.url,
				ServiceAccountEmail: saEmail,
				Scopes:              []string{"https://www.googleapis.com/auth/cloud-platform"},
			})
			require.NoError(t, err)
			// TODO: verify if its an actual token
		})
	}

}

func TestOauthToken(t *testing.T) {

	saEmail := os.Getenv("CICD_SA_EMAIL")
	saPEM := os.Getenv("CICD_SA_PEM")

	keyID, _, err := loadKey(t, saPEM)
	require.NoError(t, err)

	tests := []struct {
		name string
		url  string
	}{
		{"label", fmt.Sprintf("pkcs11:model=SoftHSM%%20v2;manufacturer=SoftHSM%%20project;token=token1;object=priv1;id=%s?pin-value=mynewpin&module-path=%s", hex.EncodeToString(keyID), lib)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewGCPPKCSCredential(&GCPPKCSConfig{
				PKCSURI:             tc.url,
				ServiceAccountEmail: saEmail,
				Scopes:              []string{"https://www.googleapis.com/auth/cloud-platform"},
				UseOauthToken:       true,
			})
			require.NoError(t, err)
			// TODO: verify if its an actual token
		})
	}
}

func TestIdToken(t *testing.T) {

	saEmail := os.Getenv("CICD_SA_EMAIL")
	saPEM := os.Getenv("CICD_SA_PEM")

	keyID, _, err := loadKey(t, saPEM)
	require.NoError(t, err)

	tests := []struct {
		name string
		url  string
	}{
		{"label", fmt.Sprintf("pkcs11:model=SoftHSM%%20v2;manufacturer=SoftHSM%%20project;token=token1;object=priv1;id=%s?pin-value=mynewpin&module-path=%s", hex.EncodeToString(keyID), lib)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewGCPPKCSCredential(&GCPPKCSConfig{
				PKCSURI:             tc.url,
				ServiceAccountEmail: saEmail,
				Scopes:              []string{"https://www.googleapis.com/auth/cloud-platform"},
				IdentityToken:       true,
				Audience:            "https://foo.bar",
			})
			require.NoError(t, err)
			// TODO: verify if its an actual token
		})
	}
}
