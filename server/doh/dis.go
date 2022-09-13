package doh

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
)

func handleDISTest(w http.ResponseWriter, r *http.Request) {
	handle := func(req *dns.Msg) *dns.Msg {
		msg, _ := dns.Exchange(req, "192.168.10.222:5301")

		return msg
	}

	var handleFn func(http.ResponseWriter, *http.Request)

	log.Info("URL Path", r.URL.Path)
	if strings.Contains(r.URL.Path, "dis-query") {
		handleFn = HandleDISQuery(handle)
	} else if r.Method == http.MethodGet && r.URL.Query().Get("dns") == "" {
		handleFn = HandleJSON(handle)
	} else {
		handleFn = HandleWireFormat(handle)
	}

	handleFn(w, r)
}

// 获取用户公钥
func getPublicKey(userid string) (string, error) {
	w := httptest.NewRecorder()

	request, err := http.NewRequest("GET", "/dis-query/userkey?userid="+userid, nil)
	if err != nil {
		return "", err
	}

	request.RemoteAddr = "127.0.0.1:0"

	handleDISTest(w, request)

	if w.Code != http.StatusOK {
		return "", errors.New("failed to query the userkey: " + userid)
	}

	data, err := ioutil.ReadAll(w.Body)
	if err != nil {
		return "", err
	}

	var uk UserKeyMsg
	err = json.Unmarshal(data, &uk)
	if err != nil {
		return "", err
	}

	if uk.UserKey != "" {
		return uk.UserKey, nil
	} else {
		return "", errors.New("failed to find the userkey: " + userid)
	}

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
