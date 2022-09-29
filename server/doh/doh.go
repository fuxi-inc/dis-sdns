package doh

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"strings"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/errmsg"
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

		returnMsg := new(ReturnMsg)

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Server", "SDNS")
		w.Header().Set("Content-Type", "application/json")

		// 查询数据地址
		if strings.Contains(path, "dataAddress") {
			dataid := r.URL.Query().Get("dataid")
			if dataid == "" {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：无法从路径query参数中获取dataid",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to get dataid", "url", r.URL.String())
				return
			}
			dataid = dns.Fqdn(dataid)

			log.Info("receive query data address", "dataid", dataid)

			qtype := dns.TypeURI

			req := new(dns.Msg)
			req.SetQuestion(dataid, qtype)
			req.SetEdns0(4096, false)
			// req.AuthenticatedData = true

			msg := handle(req)
			if msg == nil {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：DNS解析无结果",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to handle the request", "req", req)
				return
			}

			if len(msg.Answer) == 0 {
				returnMsg = &ReturnMsg{
					Status: http.StatusNotFound,
					Data:   nil,
					// Message: "失败：数据地址不存在",
					Message: errmsg.GetErrMsg(http.StatusNotFound),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to find the dataAddress", "dataid", dataid)
				return
			}
			a := msg.Answer[0]

			tmp := strings.TrimPrefix(a.String(), a.Header().String())
			slice := strings.Split(tmp, " ")
			if len(slice) != 3 {
				returnMsg = &ReturnMsg{
					Status: http.StatusNotFound,
					Data:   nil,
					// Message: "失败：无法从结果RR中获取数据地址",
					Message: errmsg.GetErrMsg(http.StatusNotFound),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to split the dataAddress from the answer RR", "answer", tmp)
				return
			}

			tmp = strings.Trim(slice[2], "\"")

			var maps = make(map[string]interface{})
			maps["dataAddress"] = tmp

			returnMsg = &ReturnMsg{
				Status:  http.StatusOK,
				Data:    maps,
				Message: errmsg.GetErrMsg(http.StatusOK),
			}

			json, err := json.Marshal(returnMsg)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			_, _ = w.Write(json)

		} else if strings.Contains(path, "userkey") {
			userid := r.URL.Query().Get("userid")
			if userid == "" {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：无法从路径query参数中获取userid",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to get userid", "url", r.URL.String())
				return
			}
			userid = dns.Fqdn(userid)

			log.Info("receive query user key", "userid", userid)

			qtype := dns.TypeCERT

			req := new(dns.Msg)
			req.SetQuestion(userid, qtype)
			req.SetEdns0(4096, false)
			// req.AuthenticatedData = true

			msg := handle(req)
			if msg == nil {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：DNS解析无结果",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to handle the request", "req", req)
				return
			}

			if len(msg.Answer) == 0 {
				returnMsg = &ReturnMsg{
					Status: http.StatusNotFound,
					Data:   nil,
					// Message: "失败：用户公钥不存在",
					Message: errmsg.GetErrMsg(http.StatusNotFound),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to find the userkey", "userid", userid)
				return
			}
			a := msg.Answer[0]

			tmp := strings.TrimPrefix(a.String(), a.Header().String())
			slice := strings.Split(tmp, " ")
			if len(slice) != 4 {
				returnMsg = &ReturnMsg{
					Status: http.StatusNotFound,
					Data:   nil,
					// Message: "失败：无法从结果RR中获取用户公钥",
					Message: errmsg.GetErrMsg(http.StatusNotFound),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to split the userkey from the answer RR", "answer", tmp)
				return
			}

			var maps = make(map[string]interface{})
			maps["userKey"] = slice[3]

			returnMsg = &ReturnMsg{
				Status:  http.StatusOK,
				Data:    maps,
				Message: errmsg.GetErrMsg(http.StatusOK),
			}

			json, err := json.Marshal(returnMsg)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			_, _ = w.Write(json)

		} else if strings.Contains(path, "podAddress") {
			userid := r.URL.Query().Get("userid")
			if userid == "" {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：无法从路径query参数中获取userid",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to get userid", "url", r.URL.String())
				return
			}
			userid = dns.Fqdn(userid)

			log.Info("receive query pod address", "userid", userid)

			qtype := dns.TypeURI

			req := new(dns.Msg)
			req.SetQuestion(userid, qtype)
			req.SetEdns0(4096, false)
			// req.AuthenticatedData = true

			msg := handle(req)
			if msg == nil {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：DNS解析无结果",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to handle the request", "req", req)
				return
			}

			if len(msg.Answer) == 0 {
				returnMsg = &ReturnMsg{
					Status: http.StatusNotFound,
					Data:   nil,
					// Message: "失败：pod地址不存在",
					Message: errmsg.GetErrMsg(http.StatusNotFound),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to find the pod address", "userid", userid)
				return
			}
			a := msg.Answer[0]

			tmp := strings.TrimPrefix(a.String(), a.Header().String())
			slice := strings.Split(tmp, " ")
			if len(slice) != 3 {
				returnMsg = &ReturnMsg{
					Status: http.StatusNotFound,
					Data:   nil,
					// Message: "失败：无法从结果RR中获取pod地址",
					Message: errmsg.GetErrMsg(http.StatusNotFound),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to split the podAddress from the answer RR", "answer", tmp)
				return
			}

			tmp = strings.Trim(slice[2], "\"")

			var maps = make(map[string]interface{})
			maps["podAddress"] = tmp

			returnMsg = &ReturnMsg{
				Status:  http.StatusOK,
				Data:    maps,
				Message: errmsg.GetErrMsg(http.StatusOK),
			}

			json, err := json.Marshal(returnMsg)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			_, _ = w.Write(json)

		} else if strings.Contains(path, "owner") {
			dataid := r.URL.Query().Get("dataid")
			if dataid == "" {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：无法从路径query参数中获取dataid",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to get dataid", "url", r.URL.String())
				return
			}
			dataid = dns.Fqdn(dataid)

			log.Info("receive query data address", "dataid", dataid)

			qtype := dns.TypeRP

			req := new(dns.Msg)
			req.SetQuestion(dataid, qtype)
			req.SetEdns0(4096, false)

			msg := handle(req)
			if msg == nil {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：DNS解析无结果",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to handle the request", "req", req)
				return
			}

			if len(msg.Answer) == 0 {
				returnMsg = &ReturnMsg{
					Status: http.StatusNotFound,
					Data:   nil,
					// Message: "失败：数据所有者不存在",
					Message: errmsg.GetErrMsg(http.StatusNotFound),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to find the ownerID", "dataid", dataid)
				return
			}
			a := msg.Answer[0]

			tmp := strings.TrimPrefix(a.String(), a.Header().String())
			slice := strings.Split(tmp, " ")
			if len(slice) != 2 {
				returnMsg = &ReturnMsg{
					Status: http.StatusNotFound,
					Data:   nil,
					// Message: "失败：无法从结果RR中获取所有者标识",
					Message: errmsg.GetErrMsg(http.StatusNotFound),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to split the ownerID from the answer RR", "answer", tmp)
				return
			}

			tmp = strings.Trim(slice[0], "\"")

			tmp2 := strings.Split(tmp, "data")
			if len(tmp2) > 2 {
				returnMsg = &ReturnMsg{
					Status: http.StatusNotFound,
					Data:   nil,
					// Message: "失败：无法从结果全名中截取到所有者ID",
					Message: errmsg.GetErrMsg(http.StatusNotFound),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to split the ownerID from the whole name", "answer", tmp)
				return
			}

			var maps = make(map[string]interface{})
			maps["owner"] = tmp2[0]

			returnMsg = &ReturnMsg{
				Status:  http.StatusOK,
				Data:    maps,
				Message: errmsg.GetErrMsg(http.StatusOK),
			}

			json, err := json.Marshal(returnMsg)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			_, _ = w.Write(json)

		} else if strings.Contains(path, "auth") {
			dataid := r.URL.Query().Get("dataid")
			if dataid == "" {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：无法从路径query参数中获取dataid",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to get dataid", "url", r.URL.String())
				return
			}
			dataid = dns.Fqdn(dataid)
			log.Info("dataid", dataid)

			log.Info("receive query data TXT", "dataid", dataid)

			qtype := dns.TypeTXT

			req := new(dns.Msg)
			req.SetQuestion(dataid, qtype)
			req.SetEdns0(4096, false)

			// req.AuthenticatedData = true

			msg := handle(req)
			if msg == nil {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：DNS解析无结果",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to handle the request", "req", req)
				return
			}

			log.Info("msg", msg.String())
			log.Info("len", len(msg.Answer))

			if len(msg.Answer) == 0 {
				returnMsg = &ReturnMsg{
					Status: http.StatusNotFound,
					Data:   nil,
					// Message: "失败：数据TXT记录不存在",
					Message: errmsg.GetErrMsg(http.StatusNotFound),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to find the data TXT", "dataid", dataid)
				return
			}
			a := msg.Answer[0]

			tmp := strings.TrimPrefix(a.String(), a.Header().String())
			if tmp == "" {
				returnMsg = &ReturnMsg{
					Status: http.StatusNotFound,
					Data:   nil,
					// Message: "失败：无法从结果RR中获取数据TXT记录",
					Message: errmsg.GetErrMsg(http.StatusNotFound),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to split the data TXT from the answer RR", "answer", tmp)
				return
			}

			var maps = make(map[string]interface{})
			maps["auth"] = tmp

			returnMsg = &ReturnMsg{
				Status:  http.StatusOK,
				Data:    maps,
				Message: errmsg.GetErrMsg(http.StatusOK),
			}

			json, err := json.Marshal(returnMsg)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			_, _ = w.Write(json)

		} else {
			returnMsg = &ReturnMsg{
				Status: http.StatusBadRequest,
				Data:   nil,
				// Message: "失败：路径错误",
				Message: errmsg.GetErrMsg(http.StatusBadRequest),
			}

			json, _ := json.Marshal(returnMsg)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(json)
			return
		}

	}
}

// HandleDIS handle dis auth request
func HandleDISAuth(handle func(*dns.Msg) *dns.Msg) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		returnMsg := new(ReturnMsg)

		w.Header().Set("Server", "SDNS")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")

		// 授权验证
		if strings.Contains(path, "authorization") {
			id := r.URL.Query().Get("dataid")
			if id == "" {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：无法从路径query参数中获取dataid",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to get dataid", "url", r.URL.String())
				return
			}
			stid := dns.Fqdn(id)

			rec := r.URL.Query().Get("userid")
			if rec == "" {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：无法从路径query参数中获取userid",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to get view user id", "url", r.URL.String())
				return
			}
			strec := dns.Fqdn(rec)

			var params AuthorizationParams

			params.Identifier = id
			params.Recipient = rec

			// 从header中获取pod签名
			sign := r.Header.Get("Authorization")
			if sign == "" {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：无法从请求Header中获取签名",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to get the pod signature", "sign", sign)
				return
			}

			args := strings.Split(sign, " ")
			if len(args) != 3 {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：无法从Authorization中截取签名",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to get the pod signature", "sign", sign)
				return
			}

			// 截取pod签名
			podSignature, err := base64.StdEncoding.DecodeString(args[1])
			if podSignature == nil || err != nil {
				returnMsg = &ReturnMsg{
					Status: http.StatusInternalServerError,
					Data:   nil,
					// Message: "失败：pod签名base64解码失败",
					Message: errmsg.GetErrMsg(http.StatusInternalServerError),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write(json)

				log.Info("failed to decode pod signature", "err", err.Error(), "sign", args[1])
				return
			}

			// 截取访问者签名
			accSignature, err := base64.StdEncoding.DecodeString(args[2])
			if accSignature == nil || err != nil {
				returnMsg = &ReturnMsg{
					Status: http.StatusInternalServerError,
					Data:   nil,
					// Message: "失败：访问签名base64解码失败",
					Message: errmsg.GetErrMsg(http.StatusInternalServerError),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write(json)

				log.Info("failed to decode signature", "err", err.Error(), "sign", args[2])
				return
			}

			// 获取访问者公钥
			qtype := dns.TypeCERT

			req := new(dns.Msg)
			req.SetQuestion(strec, qtype)
			req.SetEdns0(4096, false)

			msg := handle(req)
			if msg == nil {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：获取访问者公钥时，DNS解析无结果",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to handle the request 1", "req", req)
				return
			}

			if len(msg.Answer) == 0 {
				returnMsg = &ReturnMsg{
					Status: http.StatusNotFound,
					Data:   nil,
					// Message: "失败：访问者公钥不存在",
					Message: errmsg.GetErrMsg(http.StatusNotFound),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to find the userkey 1", "userid", rec)
				return
			}
			a := msg.Answer[0]

			tmp := strings.TrimPrefix(a.String(), a.Header().String())
			slice := strings.Split(tmp, " ")
			if len(slice) != 4 {
				returnMsg = &ReturnMsg{
					Status: http.StatusNotFound,
					Data:   nil,
					// Message: "失败：无法从结果RR中获取访问者公钥",
					Message: errmsg.GetErrMsg(http.StatusNotFound),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to split the userkey from the answer RR", "answer", tmp)
				return
			}

			pK := slice[3]

			// 转换公钥格式
			publicKey, err := importPublicKey(pK)
			if err != nil {
				returnMsg = &ReturnMsg{
					Status: http.StatusInternalServerError,
					Data:   nil,
					// Message: "失败：无法将公钥转换为rsa.PublicKey",
					Message: errmsg.GetErrMsg(http.StatusInternalServerError),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write(json)

				log.Info("failed to transfer to rsa.Publickey", "err", err.Error())
				return
			}

			// 验证访问者签名
			err = verifySignature(publicKey, hash([]byte(id+rec)), accSignature)
			if err != nil {
				returnMsg = &ReturnMsg{
					Status: http.StatusUnauthorized,
					Data:   nil,
					// Message: "失败：访问者签名验证未通过",
					Message: errmsg.GetErrMsg(http.StatusUnauthorized),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write(json)

				log.Info("failed to verify the access signature", "err", err.Error(), "dataid", id, "userid", rec, "pk", pK, "sign", args[2])
				return
			}

			// 获取数据标识对应身份（pod）标识
			qtype = dns.TypeRP

			req = new(dns.Msg)
			req.SetQuestion(stid, qtype)
			req.SetEdns0(4096, false)

			msg = handle(req)
			if msg == nil {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：DNS解析无结果",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to handle the request 2", "req", req)
				return
			}

			if len(msg.Answer) == 0 {
				returnMsg = &ReturnMsg{
					Status: http.StatusNotFound,
					Data:   nil,
					// Message: "失败：所有者标识不存在",
					Message: errmsg.GetErrMsg(http.StatusNotFound),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to find the ownerID", "userid", rec)
				return
			}
			a = msg.Answer[0]

			tmp = strings.TrimPrefix(a.String(), a.Header().String())
			log.Info("tmp", tmp)

			slice = strings.Split(tmp, " ")
			if len(slice) != 2 {
				returnMsg = &ReturnMsg{
					Status: http.StatusNotFound,
					Data:   nil,
					// Message: "失败：无法从结果RR中获取所有者标识",
					Message: errmsg.GetErrMsg(http.StatusNotFound),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to split the ownerID  from the answer RR", "answer", tmp)
				return
			}

			tmp = strings.Trim(slice[0], "\"")

			tmp2 := strings.Split(tmp, "data")
			if len(tmp2) > 2 {
				returnMsg = &ReturnMsg{
					Status: http.StatusNotFound,
					Data:   nil,
					// Message: "失败：无法从结果全名中截取到所有者ID",
					Message: errmsg.GetErrMsg(http.StatusNotFound),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to split the ownerID from the whole name", "answer", tmp)
				return
			}

			owner := tmp2[0]

			// 获取pod所有者公钥
			qtype = dns.TypeCERT

			req = new(dns.Msg)
			req.SetQuestion(owner, qtype)
			req.SetEdns0(4096, false)

			msg = handle(req)
			if msg == nil {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：解析授权TXT记录时，DNS解析无结果",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to handle the request 3", "req", req)
				return
			}

			if len(msg.Answer) == 0 {
				returnMsg = &ReturnMsg{
					Status: http.StatusNotFound,
					Data:   nil,
					// Message: "失败：POD所有者公钥不存在",
					Message: errmsg.GetErrMsg(http.StatusNotFound),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to find the userkey2", "userid", owner)
				return
			}
			a = msg.Answer[0]

			tmp = strings.TrimPrefix(a.String(), a.Header().String())
			slice = strings.Split(tmp, " ")
			if len(slice) != 4 {
				returnMsg = &ReturnMsg{
					Status: http.StatusNotFound,
					Data:   nil,
					// Message: "失败：无法从结果RR中获取POD所有者公钥",
					Message: errmsg.GetErrMsg(http.StatusNotFound),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to split the userkey from the answer RR", "answer", tmp)
				return
			}

			pK = slice[3]

			// 转换公钥格式
			publicKey, err = importPublicKey(pK)
			if err != nil {
				returnMsg = &ReturnMsg{
					Status: http.StatusInternalServerError,
					Data:   nil,
					// Message: "失败：无法将公钥转换为rsa.PublicKey",
					Message: errmsg.GetErrMsg(http.StatusInternalServerError),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write(json)

				log.Info("failed to transfer to rsa.Publickey", "err", err.Error())
				return
			}

			// 验证pod所有者签名
			err = verifySignature(publicKey, hash([]byte(id+rec)), podSignature)
			if err != nil {
				returnMsg = &ReturnMsg{
					Status: http.StatusUnauthorized,
					Data:   nil,
					// Message: "失败：POD所有者签名验证未通过",
					Message: errmsg.GetErrMsg(http.StatusUnauthorized),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write(json)

				log.Info("failed to verify the pod signature", "err", err.Error())
				return
			}

			// 验证授权(获取授权TXT记录)
			// TODO
			buserid := base32.StdEncoding.EncodeToString(hash([]byte(rec)))

			qtype = dns.TypeTXT

			req = new(dns.Msg)
			request := buserid + "." + stid

			req.SetQuestion(request, qtype)
			req.SetEdns0(4096, false)

			msg = handle(req)
			if msg == nil {
				returnMsg = &ReturnMsg{
					Status: http.StatusForbidden,
					Data:   nil,
					// Message: "失败：授权TXT记录DNS解析无结果，授权验证未通过",
					Message: errmsg.GetErrMsg(http.StatusForbidden),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write(json)

				log.Info("failed to handle the request", "req", req)
				return
			}

			if len(msg.Answer) == 0 {
				returnMsg = &ReturnMsg{
					Status: http.StatusForbidden,
					Data:   nil,
					// Message: "失败：授权TXT记录不存在，授权验证未通过",
					Message: errmsg.GetErrMsg(http.StatusForbidden),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write(json)

				log.Info("failed to find the authorization TXT", "authid", request)
				return
			}
			a = msg.Answer[0]

			tmp = strings.TrimPrefix(a.String(), a.Header().String())
			if tmp == "" {
				returnMsg = &ReturnMsg{
					Status: http.StatusForbidden,
					Data:   nil,
					// Message: "失败：无法从结果RR中获取授权TXT记录，授权验证未通过",
					Message: errmsg.GetErrMsg(http.StatusForbidden),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write(json)

				log.Info("failed to split the authorization TXT from the answer RR", "answer", tmp)
				return
			}

			var maps = make(map[string]interface{})
			maps["auth"] = tmp

			returnMsg = &ReturnMsg{
				Status:  http.StatusOK,
				Data:    maps,
				Message: errmsg.GetErrMsg(http.StatusOK),
			}

			json, err := json.Marshal(returnMsg)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			_, _ = w.Write(json)

		} else if strings.Contains(path, "integrity") {
			dataid := r.URL.Query().Get("dataid")
			if dataid == "" {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：无法从路径query参数中获取dataid",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to get dataid", "url", r.URL.String())
				return
			}
			dataid = dns.Fqdn(dataid)

			dataDigest := r.URL.Query().Get("dataDigest")
			if dataDigest == "" {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：无法从路径query参数中获取dataDigest",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to get dataDigest", "url", r.URL.String())
				return
			}

			// 获取数据完整性记录
			qtype := dns.TypeTXT

			req := new(dns.Msg)
			req.SetQuestion(dataid, qtype)
			req.SetEdns0(4096, false)

			msg := handle(req)
			if msg == nil {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：DNS解析无结果",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to handle the request", "req", req)
				return
			}

			if len(msg.Answer) == 0 {
				returnMsg = &ReturnMsg{
					Status: http.StatusNotFound,
					Data:   nil,
					// Message: "失败：数据TXT记录不存在",
					Message: errmsg.GetErrMsg(http.StatusNotFound),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to find the data TXT", "dataid", dataid)
				return
			}
			a := msg.Answer[0]

			tmp := strings.TrimPrefix(a.String(), a.Header().String())
			if tmp == "" {
				returnMsg = &ReturnMsg{
					Status: http.StatusNotFound,
					Data:   nil,
					// Message: "失败：无法从结果RR中获取数据TXT记录",
					Message: errmsg.GetErrMsg(http.StatusNotFound),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to split the data TXT from the answer RR", "answer", tmp)
				return
			}
			tmp = strings.Trim(tmp, "\"")

			// 判断摘要是否相同
			if tmp != dataDigest {
				returnMsg = &ReturnMsg{
					Status: http.StatusForbidden,
					Data:   nil,
					// Message: "失败：摘要不匹配，完整性验证未通过",
					Message: errmsg.GetErrMsg(http.StatusForbidden),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write(json)

				log.Info("integrity authentication failed", "tmp", tmp, "dataDigest", dataDigest)
				return
			}

			var maps = make(map[string]interface{})
			maps["integrity"] = true

			returnMsg = &ReturnMsg{
				Status:  http.StatusOK,
				Data:    maps,
				Message: errmsg.GetErrMsg(http.StatusOK),
			}

			json, err := json.Marshal(returnMsg)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			_, _ = w.Write(json)

		} else if strings.Contains(path, "identity") {
			id := r.URL.Query().Get("userid")
			if id == "" {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：无法从路径query参数中获取userid",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to get userid", "url", r.URL.String())
				return
			}
			stid := dns.Fqdn(id)

			//从header中获取签名
			sign := r.Header.Get("Authorization")
			if sign == "" {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：无法从请求Header中获取identity签名",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to get the identity signature", "sign", sign)
				return
			}

			args := strings.Split(sign, " ")
			if len(args) != 2 {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：无法从Authorization中截取identity签名",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to get the identity signature", "sign", sign)
				return
			}

			signature, err := base64.StdEncoding.DecodeString(args[1])
			if signature == nil || err != nil {
				returnMsg = &ReturnMsg{
					Status: http.StatusInternalServerError,
					Data:   nil,
					// Message: "失败：identity签名base64解码失败",
					Message: errmsg.GetErrMsg(http.StatusInternalServerError),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write(json)

				log.Info("failed to decode identity signature", "err", err.Error())
				return
			}

			// 获取identity公钥
			qtype := dns.TypeCERT

			req := new(dns.Msg)
			req.SetQuestion(stid, qtype)
			req.SetEdns0(4096, false)

			msg := handle(req)
			if msg == nil {
				returnMsg = &ReturnMsg{
					Status: http.StatusBadRequest,
					Data:   nil,
					// Message: "失败：获取identity公钥时，DNS解析无结果",
					Message: errmsg.GetErrMsg(http.StatusBadRequest),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to handle the identity cert request ", "req", req)
				return
			}

			if len(msg.Answer) == 0 {
				returnMsg = &ReturnMsg{
					Status: http.StatusNotFound,
					Data:   nil,
					// Message: "失败：identity公钥不存在",
					Message: errmsg.GetErrMsg(http.StatusNotFound),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to find the identity userkey", "userid", id)
				return
			}
			a := msg.Answer[0]

			tmp := strings.TrimPrefix(a.String(), a.Header().String())
			slice := strings.Split(tmp, " ")
			if len(slice) != 4 {
				returnMsg = &ReturnMsg{
					Status: http.StatusNotFound,
					Data:   nil,
					// Message: "失败：无法从结果RR中获取identitiy公钥",
					Message: errmsg.GetErrMsg(http.StatusNotFound),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to split the identity userkey from the answer RR", "answer", tmp)
				return
			}

			pK := slice[3]

			// 转换公钥格式
			publicKey, err := importPublicKey(pK)
			if err != nil {
				returnMsg = &ReturnMsg{
					Status: http.StatusInternalServerError,
					Data:   nil,
					// Message: "失败：无法将公钥转换为rsa.PublicKey",
					Message: errmsg.GetErrMsg(http.StatusInternalServerError),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write(json)

				log.Info("failed to transfer to rsa.Publickey", "err", err.Error())
				return
			}

			// 构造签名struct
			authSign := &AuthIdentitySign{
				ID: id,
			}

			signAsBytes, err := json.Marshal(authSign)
			if err != nil {
				returnMsg = &ReturnMsg{
					Status: http.StatusInternalServerError,
					Data:   nil,
					// Message: "marshal签名体失败",
					Message: errmsg.GetErrMsg(http.StatusInternalServerError),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write(json)

				log.Info("failed to marshal the body for identity auth sign", "err", err.Error())
				return
			}

			// 验证identity所有者签名
			err = verifySignature(publicKey, hash(signAsBytes), signature)
			if err != nil {

				var maps = make(map[string]interface{})
				maps["pass"] = false

				returnMsg = &ReturnMsg{
					Status: http.StatusUnauthorized,
					Data:   maps,
					// Message: "失败：identity所有者签名验证未通过",
					Message: errmsg.GetErrMsg(http.StatusUnauthorized),
				}

				json, _ := json.Marshal(returnMsg)
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write(json)

				log.Info("failed to verify the identity signature", "err", err.Error())
				return
			}

			var maps = make(map[string]interface{})
			maps["pass"] = true

			returnMsg = &ReturnMsg{
				Status:  http.StatusOK,
				Data:    maps,
				Message: errmsg.GetErrMsg(http.StatusOK),
			}

			json, err := json.Marshal(returnMsg)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			_, _ = w.Write(json)

		} else {
			returnMsg = &ReturnMsg{
				Status: http.StatusBadRequest,
				Data:   nil,
				// Message: "失败：路径错误",
				Message: errmsg.GetErrMsg(http.StatusBadRequest),
			}

			json, _ := json.Marshal(returnMsg)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(json)

			return
		}

	}
}
