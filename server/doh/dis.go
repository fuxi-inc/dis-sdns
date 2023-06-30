package doh

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/spf13/viper"
)

var vc = viper.New()

type UserCredential struct {
	Id         string `mapstructure:"id"`
	PrivateKey string `mapstructure:"private_key"`
	PublicKey  string `mapstructure:"public_key"`
}

func handleDISTest(w http.ResponseWriter, r *http.Request) {
	handle := func(req *dns.Msg) *dns.Msg {

		// TODO: 改权威地址
		msg, _ := dns.Exchange(req, "106.14.192.31:5301")

		return msg
	}

	var handleFn func(http.ResponseWriter, *http.Request)

	log.Info("URL Path", r.URL.Path)
	if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "DataObject") {
		handleFn = HandleDISQuery(handle)
	} else if r.Method == http.MethodGet && r.URL.Query().Get("dns") == "" {
		handleFn = HandleJSON(handle)
	} else {
		handleFn = HandleWireFormat(handle)
	}

	handleFn(w, r)
}

func importPublicKey(pubKey string) (*rsa.PublicKey, error) {

	publicKeyAsBytes, err := base64.StdEncoding.DecodeString(pubKey)
	if err != nil {
		return nil, err
	}

	publicKey, err := x509.ParsePKCS1PublicKey(publicKeyAsBytes)
	if err != nil {
		return nil, err
	}

	return publicKey, err
}

func importPrivateKey(privKey string) (*rsa.PrivateKey, error) {

	privateKeyAsBytes, err := base64.StdEncoding.DecodeString(privKey)
	if err != nil {
		return nil, err
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyAsBytes)
	if err != nil {
		return nil, err
	}

	return privateKey, err
}

func sign(privateKey *rsa.PrivateKey, hashMsg []byte) ([]byte, error) {

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashMsg)
	if err != nil {
		return nil, errors.New("failed to sign the signature")
	}

	return signature, nil
}

func verifySignature(publicKey *rsa.PublicKey, hashMsg []byte, signature []byte) error {

	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashMsg, signature)
	if err != nil {
		return errors.New("failed to verify the signature")
	}

	return nil
}

func hash(msg []byte) []byte {

	hash := sha256.New()
	_, err := hash.Write(msg)
	if err != nil {
		panic(err)
	}

	return hash.Sum(nil)
}

func loadUserCredentials(filepath string) (*UserCredential, error) {
	if filepath == "" {
		filepath = vc.GetString("CONFIG_PATH")
		if filepath == "" {
			filepath = "userconfig.yaml"
		}
	}
	vc.SetConfigFile(filepath)
	err := vc.ReadInConfig()
	if err != nil {
		return nil, errors.New("读取配置文件失败")
	}

	var credential UserCredential
	err = vc.Unmarshal(&credential)
	if err != nil {
		return nil, errors.New("解析身份认证信息失败")
	}

	return &credential, nil
}

func fetchKeyPair(credential *UserCredential) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privKey, err := importPrivateKey(credential.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	pubKey, err := importPublicKey(credential.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return privKey, pubKey, err
}
