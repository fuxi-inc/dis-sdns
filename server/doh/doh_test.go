package doh

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/stretchr/testify/assert"
)

func handleTest(w http.ResponseWriter, r *http.Request) {
	handle := func(req *dns.Msg) *dns.Msg {
		msg, _ := dns.Exchange(req, "8.8.8.8:53")

		return msg
	}

	var handleFn func(http.ResponseWriter, *http.Request)
	if r.Method == http.MethodGet && r.URL.Query().Get("dns") == "" {
		handleFn = HandleJSON(handle)
	} else {
		handleFn = HandleWireFormat(handle)
	}

	handleFn(w, r)
}

func Test_disQuery(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()

	// 测试数据地址查询
	request, err := http.NewRequest("GET", "/dis-query/dataAddress?dataid=09faf1a7-963a-4799-a476-99804588835f.data.fuxi.", nil)
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"

	handleDISTest(w, request)

	assert.Equal(t, w.Code, http.StatusOK)

	data, err := ioutil.ReadAll(w.Body)
	assert.NoError(t, err)

	log.Info("data", string(data))
	var dm DataAddressMsg
	err = json.Unmarshal(data, &dm)
	assert.NoError(t, err)

	log.Info("DataAddress", dm.DataAddress)
	assert.Equal(t, len(dm.DataAddress) > 0, true)

	// 测试身份公钥查询
	w = httptest.NewRecorder()

	request, err = http.NewRequest("GET", "/dis-query/userkey?userid=weijiuqi.user.fuxi.", nil)
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"

	handleDISTest(w, request)

	assert.Equal(t, w.Code, http.StatusOK)

	data, err = ioutil.ReadAll(w.Body)
	assert.NoError(t, err)

	log.Info("data", string(data))

	var uk UserKeyMsg
	err = json.Unmarshal(data, &uk)
	assert.NoError(t, err)

	log.Info("UserKey", uk.UserKey)
	assert.Equal(t, len(uk.UserKey) > 0, true)

	// 测试POD地址查询
	w = httptest.NewRecorder()

	request, err = http.NewRequest("GET", "/dis-query/podAddress?userid=weijiuqi.user.fuxi", nil)
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"

	handleDISTest(w, request)

	assert.Equal(t, w.Code, http.StatusOK)

	data, err = ioutil.ReadAll(w.Body)
	assert.NoError(t, err)

	log.Info("data", string(data))

	var pa PodAddressMsg
	err = json.Unmarshal(data, &pa)
	assert.NoError(t, err)

	log.Info("PodAddress", pa.PodAddress)
	assert.Equal(t, len(pa.PodAddress) > 0, true)

	// 测试所有者标识（RP）
	w = httptest.NewRecorder()

	request, err = http.NewRequest("GET", "/dis-query/owner?dataid=09faf1a7-963a-4799-a476-99804588835f.data.fuxi.", nil)
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"

	handleDISTest(w, request)

	assert.Equal(t, w.Code, http.StatusOK)

	data, err = ioutil.ReadAll(w.Body)
	assert.NoError(t, err)

	log.Info("data", string(data))

	var ow OwnerMsg
	err = json.Unmarshal(data, &ow)
	assert.NoError(t, err)

	log.Info("OwnerID", ow.OwnerID)
	assert.Equal(t, len(ow.OwnerID) > 0, true)

	// 测试数据完整性记录（TXT）查询
	w = httptest.NewRecorder()

	request, err = http.NewRequest("GET", "/dis-query/auth?dataid=21ba902b-42d3-4633-9d92-ce5a709c478f.data.fuxi.", nil)
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"

	handleDISTest(w, request)

	assert.Equal(t, w.Code, http.StatusOK)

	data, err = ioutil.ReadAll(w.Body)
	assert.NoError(t, err)

	log.Info("data", string(data))

	var au AuthMsg
	err = json.Unmarshal(data, &au)
	assert.NoError(t, err)

	log.Info("AuthTXT", au.Auth)
	assert.Equal(t, len(au.Auth) > 0, true)

	// 授权验证
	// w = httptest.NewRecorder()

	// request, err = http.NewRequest("POST", "/dis-auth/authorization?dataid=AWI346YBNIHHNLUB5FWUXJLIYM7TXYNOFHHU77FSEGERQZQ3W5CA====.b0494c9d-b624-4897-ab11-7450fa53b718.data.fuxi.", nil)
	// assert.NoError(t, err)

	// request.RemoteAddr = "127.0.0.1:0"

	// handleDISTest(w, request)

	// assert.Equal(t, w.Code, http.StatusOK)

	// data, err = ioutil.ReadAll(w.Body)
	// assert.NoError(t, err)

	// log.Info("data", string(data))

	// var autho AuthMsg
	// err = json.Unmarshal(data, &autho)
	// assert.NoError(t, err)

	// log.Info("AuthTXT", au.Auth)
	// assert.Equal(t, len(au.Auth) > 0, true)
}

func Test_dohJSON(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("GET", "/dns-query?name=www.google.com&type=a&do=true&cd=true", nil)
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"

	handleTest(w, request)

	assert.Equal(t, w.Code, http.StatusOK)

	data, err := ioutil.ReadAll(w.Body)
	assert.NoError(t, err)

	var dm Msg
	err = json.Unmarshal(data, &dm)
	assert.NoError(t, err)

	assert.Equal(t, len(dm.Answer) > 0, true)

}

func Test_dohJSONerror(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("GET", "/dns-query?name=", nil)
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"

	handleTest(w, request)

	assert.Equal(t, w.Code, http.StatusBadRequest)
}

func Test_dohJSONaccepthtml(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("GET", "/dns-query?name=www.google.com", nil)
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"

	request.Header.Add("Accept", "text/html")
	handleTest(w, request)

	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Header().Get("Content-Type"), "application/x-javascript")
}

func Test_dohWireGET(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()

	req := new(dns.Msg)
	req.SetQuestion("www.google.com.", dns.TypeA)
	req.RecursionDesired = true

	data, err := req.Pack()
	assert.NoError(t, err)

	dq := base64.RawURLEncoding.EncodeToString(data)

	request, err := http.NewRequest("GET", fmt.Sprintf("/dns-query?dns=%s", dq), nil)
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"

	handleTest(w, request)

	assert.Equal(t, w.Code, http.StatusOK)

	data, err = ioutil.ReadAll(w.Body)
	assert.NoError(t, err)

	msg := new(dns.Msg)
	err = msg.Unpack(data)
	assert.NoError(t, err)

	assert.Equal(t, msg.Rcode, dns.RcodeSuccess)

	assert.Equal(t, len(msg.Answer) > 0, true)
}

func Test_dohWireGETerror(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("GET", "/dns-query?dns=", nil)
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"

	handleTest(w, request)

	assert.Equal(t, w.Code, http.StatusBadRequest)
}

func Test_dohWireGETbadquery(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("GET", "/dns-query?dns=Df4", nil)
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"

	handleTest(w, request)

	assert.Equal(t, w.Code, http.StatusBadRequest)
}

func Test_dohWireHEAD(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("HEAD", "/dns-query?dns=", nil)
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"

	handleTest(w, request)

	assert.Equal(t, w.Code, http.StatusMethodNotAllowed)
}

func Test_dohWirePOST(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()

	req := new(dns.Msg)
	req.SetQuestion("www.google.com.", dns.TypeA)
	req.RecursionDesired = true

	data, err := req.Pack()
	assert.NoError(t, err)

	request, err := http.NewRequest("POST", "/dns-query", bytes.NewReader(data))
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"
	request.Header.Add("Content-Type", "application/dns-message")

	handleTest(w, request)

	assert.Equal(t, w.Code, http.StatusOK)

	data, err = ioutil.ReadAll(w.Body)
	assert.NoError(t, err)

	msg := new(dns.Msg)
	err = msg.Unpack(data)
	assert.NoError(t, err)

	assert.Equal(t, msg.Rcode, dns.RcodeSuccess)

	assert.Equal(t, len(msg.Answer) > 0, true)
}

func Test_dohWirePOSTError(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("POST", "/dns-query", bytes.NewReader([]byte{}))
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"
	request.Header.Add("Content-Type", "text/html")

	handleTest(w, request)

	assert.Equal(t, w.Code, http.StatusUnsupportedMediaType)
}
