package doh

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"strings"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
)

// HandleWireFormat handle wire format
func HandleWireFormat(handle func(*dns.Msg) *dns.Msg) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			buf []byte
			err error
		)

		switch r.Method {
		case http.MethodGet:
			buf, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
			if len(buf) == 0 || err != nil {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
		case http.MethodPost:
			if r.Header.Get("Content-Type") != "application/dns-message" {
				http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
				return
			}

			buf, err = ioutil.ReadAll(r.Body)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			defer r.Body.Close()
		default:
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		req := new(dns.Msg)
		if err := req.Unpack(buf); err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		msg := handle(req)
		if msg == nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		packed, err := msg.Pack()
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Server", "SDNS")
		w.Header().Set("Content-Type", "application/dns-message")

		_, _ = w.Write(packed)
	}
}

// HandleJSON handle json format
func HandleJSON(handle func(*dns.Msg) *dns.Msg) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		name = dns.Fqdn(name)

		qtype := ParseQTYPE(r.URL.Query().Get("type"))
		if qtype == dns.TypeNone {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		req := new(dns.Msg)
		req.SetQuestion(name, qtype)
		// req.AuthenticatedData = true

		if r.URL.Query().Get("cd") == "true" {
			req.CheckingDisabled = true
		}

		opt := &dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".",
				Class:  dns.DefaultMsgSize,
				Rrtype: dns.TypeOPT,
			},
		}

		if r.URL.Query().Get("do") == "true" {
			opt.SetDo()
		}

		if ecs := r.URL.Query().Get("edns_client_subnet"); ecs != "" {
			_, subnet, err := net.ParseCIDR(ecs)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			mask, bits := subnet.Mask.Size()
			var af uint16
			if bits == 32 {
				af = 1
			} else {
				af = 2
			}

			opt.Option = []dns.EDNS0{
				&dns.EDNS0_SUBNET{
					Code:          dns.EDNS0SUBNET,
					Family:        af,
					SourceNetmask: uint8(mask),
					SourceScope:   0,
					Address:       subnet.IP,
				},
			}
		}

		req.Extra = append(req.Extra, opt)

		log.Info("request", req.Question[0].String())

		msg := handle(req)
		if msg == nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		json, err := json.Marshal(NewMsg(msg))
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Server", "SDNS")

		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			w.Header().Set("Content-Type", "application/x-javascript")
		} else {
			w.Header().Set("Content-Type", "application/dns-json")
		}

		_, _ = w.Write(json)
	}
}

// HandleDIS handle dis query request
func HandleDISQuery(handle func(*dns.Msg) *dns.Msg) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// 查询数据地址
		if strings.Contains(path, "dataAddress") {
			dataid := r.URL.Query().Get("dataid")
			if dataid == "" {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				log.Info("failed to get dataid", "url", r.URL.String())
				return
			}
			dataid = dns.Fqdn(dataid)

			log.Info("receive query data address", "dataid", dataid)

			qtype := dns.TypeURI

			req := new(dns.Msg)
			req.SetQuestion(dataid, qtype)
			// req.AuthenticatedData = true

			msg := handle(req)
			if msg == nil {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				log.Info("failed to handle the request", "req", req)
				return
			}

			if len(msg.Answer) == 0 {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				log.Info("failed to find the dataAddress", "dataid", dataid)
				return
			}
			a := msg.Answer[0]

			tmp := strings.TrimPrefix(a.String(), a.Header().String())
			slice := strings.Split(tmp, " ")
			if len(slice) != 3 {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				log.Info("failed to split the dataAddress from the answer RR", "answer", tmp)
				return
			}

			tmp = strings.Trim(slice[2], "\"")

			dataAddress := &DataAddressMsg{
				DataAddress: tmp,
			}

			json, err := json.Marshal(dataAddress)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Server", "SDNS")
			w.Header().Set("Content-Type", "application/dns-json")

			_, _ = w.Write(json)

		} else if strings.Contains(path, "userkey") {
			userid := r.URL.Query().Get("userid")
			if userid == "" {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				log.Info("failed to get userid", "url", r.URL.String())
				return
			}
			userid = dns.Fqdn(userid)

			log.Info("receive query user key", "userid", userid)

			qtype := dns.TypeCERT

			req := new(dns.Msg)
			req.SetQuestion(userid, qtype)
			// req.AuthenticatedData = true

			msg := handle(req)
			if msg == nil {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				log.Info("failed to handle the request", "req", req)
				return
			}

			if len(msg.Answer) == 0 {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				log.Info("failed to find the userkey", "userid", userid)
				return
			}
			a := msg.Answer[0]

			tmp := strings.TrimPrefix(a.String(), a.Header().String())
			slice := strings.Split(tmp, " ")
			if len(slice) != 4 {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				log.Info("failed to split the userkey from the answer RR", "answer", tmp)
				return
			}

			userKey := &UserKeyMsg{
				UserKey: slice[3],
			}

			json, err := json.Marshal(userKey)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Server", "SDNS")
			w.Header().Set("Content-Type", "application/dns-json")

			_, _ = w.Write(json)

		} else if strings.Contains(path, "podAddress") {
			userid := r.URL.Query().Get("userid")
			if userid == "" {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				log.Info("failed to get userid", "url", r.URL.String())
				return
			}
			userid = dns.Fqdn(userid)

			log.Info("receive query pod address", "userid", userid)

			qtype := dns.TypeURI

			req := new(dns.Msg)
			req.SetQuestion(userid, qtype)
			// req.AuthenticatedData = true

			msg := handle(req)
			if msg == nil {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				log.Info("failed to handle the request", "req", req)
				return
			}

			if len(msg.Answer) == 0 {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				log.Info("failed to find the pod address", "userid", userid)
				return
			}
			a := msg.Answer[0]

			tmp := strings.TrimPrefix(a.String(), a.Header().String())
			slice := strings.Split(tmp, " ")
			if len(slice) != 3 {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				log.Info("failed to split the podAddress from the answer RR", "answer", tmp)
				return
			}

			tmp = strings.Trim(slice[2], "\"")

			podAddress := &PodAddressMsg{
				PodAddress: tmp,
			}

			json, err := json.Marshal(podAddress)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Server", "SDNS")
			w.Header().Set("Content-Type", "application/dns-json")

			_, _ = w.Write(json)

		} else if strings.Contains(path, "owner") {
			dataid := r.URL.Query().Get("dataid")
			if dataid == "" {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				log.Info("failed to get dataid", "url", r.URL.String())
				return
			}
			dataid = dns.Fqdn(dataid)

			log.Info("receive query data address", "dataid", dataid)

			qtype := dns.TypeRP

			req := new(dns.Msg)
			req.SetQuestion(dataid, qtype)

			msg := handle(req)
			if msg == nil {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				log.Info("failed to handle the request", "req", req)
				return
			}

			if len(msg.Answer) == 0 {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				log.Info("failed to find the ownerID", "dataid", dataid)
				return
			}
			a := msg.Answer[0]

			tmp := strings.TrimPrefix(a.String(), a.Header().String())
			slice := strings.Split(tmp, " ")
			if len(slice) != 2 {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				log.Info("failed to split the ownerID from the answer RR", "answer", tmp)
				return
			}

			tmp = strings.Trim(slice[0], "\"")

			owner := &OwnerMsg{
				OwnerID: tmp,
			}

			json, err := json.Marshal(owner)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Server", "SDNS")
			w.Header().Set("Content-Type", "application/dns-json")

			_, _ = w.Write(json)

		} else if strings.Contains(path, "auth") {
			dataid := r.URL.Query().Get("dataid")
			if dataid == "" {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				log.Info("failed to get dataid", "url", r.URL.String())
				return
			}
			dataid = dns.Fqdn(dataid)

			log.Info("receive query data TXT", "dataid", dataid)

			qtype := dns.TypeTXT

			req := new(dns.Msg)
			req.SetQuestion(dataid, qtype)
			// req.AuthenticatedData = true

			msg := handle(req)
			if msg == nil {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				log.Info("failed to handle the request", "req", req)
				return
			}

			if len(msg.Answer) == 0 {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				log.Info("failed to find the data TXT", "dataid", dataid)
				return
			}
			a := msg.Answer[0]

			tmp := strings.TrimPrefix(a.String(), a.Header().String())
			if tmp == "" {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				log.Info("failed to split the data TXT from the answer RR", "answer", tmp)
				return
			}

			auth := &AuthMsg{
				Auth: tmp,
			}

			json, err := json.Marshal(auth)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Server", "SDNS")
			w.Header().Set("Content-Type", "application/dns-json")

			_, _ = w.Write(json)
		} else {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

	}
}

// HandleDIS handle dis auth request
func HandleDISAuth(handle func(*dns.Msg) *dns.Msg) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// 授权验证
		if strings.Contains(path, "authorization") {
			var params AuthorizationParams

			if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				log.Info("failed to decode request body", "err", err.Error())
				return
			}

			id := params.Identifier
			rec := params.Recipient

			if id == "" || rec == "" {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				paramsJson, _ := json.Marshal(params)
				log.Info("failed to get one of the params", "params", string(paramsJson))
				return
			}

			// 从header中获取pod签名
			sign := r.Header.Get("Authorization")
			if sign == "" {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				log.Info("failed to get the pod signature", "sign", sign)
				return
			}

			args := strings.Split(sign, " ")
			if len(args) != 3 {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				log.Info("failed to get the pod signature", "sign", sign)
				return
			}

			// 截取pod签名
			podSignature, err := base64.StdEncoding.DecodeString(args[1])
			if podSignature == nil || err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				log.Info("failed to decode signature", "err", err.Error())
				return
			}

			// 截取访问者签名
			accSignature, err := base64.StdEncoding.DecodeString(args[2])
			if accSignature == nil || err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				log.Info("failed to decode signature", "err", err.Error())
				return
			}

			// 获取访问者公钥
			pK, err := getPublicKey(rec)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				log.Info("failed to find the userkey", "userid", rec, "error", err)
				return
			}

			publicKey, err := importPublicKey(pK)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				log.Info("failed to transfer to rsa.Publickey", "err", err.Error())
				return
			}

			requestAsBytes, err := json.Marshal(params)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				log.Info("failed to marshal", "err", err.Error())
				return
			}

			// 验证访问者签名
			err = verifySignature(publicKey, hash(requestAsBytes), accSignature)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				log.Info("failed to verify the access signature", "err", err.Error())
				return
			}

			// 获取数据标识对应身份（pod）标识
			owner, err := getOwnerID(id)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				log.Info("failed to find the ownerID", "dataid", id, "error", err)
				return
			}

			// 获取pod所有者公钥
			pK, err = getPublicKey(owner)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				log.Info("failed to find the userkey", "userid", owner, "error", err)
				return
			}

			publicKey, err = importPublicKey(pK)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				log.Info("failed to transfer to rsa.Publickey", "err", err.Error())
				return
			}

			// 验证pod所有者签名
			err = verifySignature(publicKey, hash(requestAsBytes), podSignature)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				log.Info("failed to verify the pod signature", "err", err.Error())
				return
			}

			// 验证授权(获取授权TXT记录)
			tmp, err := getAuthorization(rec, id)
			if err != nil || tmp == "" {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				log.Info("failed to find the ownerID", "dataid", id, "error", err)
				return
			}

			auth := &AuthMsg{
				Auth: tmp,
			}

			json, err := json.Marshal(auth)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Server", "SDNS")
			w.Header().Set("Content-Type", "application/dns-json")

			_, _ = w.Write(json)

		} else {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusMethodNotAllowed)
			return
		}

	}
}
