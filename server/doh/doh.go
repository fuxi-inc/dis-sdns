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
	"github.com/semihalev/sdns/server/errmsg"
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
		// path := r.URL.Path

		// returnMsg := new(errmsg.err)

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Server", "SDNS")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		// 总体查询
		doi := r.URL.Query().Get("doi")
		body := r.URL.Query().Get("type")

		// 查询参数缺失
		if doi == "" {
			json, _ := json.Marshal(errmsg.ErrnoDoiParamsError)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(json)

			log.Info("failed to get doi from query url", "url", r.URL.String())
			return
		}

		// 响应结果
		var maps = make(map[string]interface{})

		// 查询Do地址dar
		if strings.Contains(body, "dar") {

			doi = dns.Fqdn(doi)

			log.Info("receive query data address", "doi", doi)

			qtype := dns.TypeURI

			req := new(dns.Msg)
			req.SetQuestion(doi, qtype)
			req.SetEdns0(4096, false)
			// req.AuthenticatedData = true

			msg := handle(req)
			if msg == nil {
				json, _ := json.Marshal(errmsg.ErrnoDomainResolutionError)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to handle the request", "req", req)
				return
			}

			if len(msg.Answer) == 0 {
				// 数据标识地址不存在
				json, _ := json.Marshal(errmsg.ErrnoDarNotFoundError)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to find the dataAddress", "doi", doi)
				return
			}
			a := msg.Answer[0]

			tmp := strings.TrimPrefix(a.String(), a.Header().String())
			slice := strings.Split(tmp, " ")
			if len(slice) != 3 {
				// 无法从结果RR中获取数据地址
				json, _ := json.Marshal(errmsg.ErrnoDarNotFoundError)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to split the dataAddress from the answer RR", "answer", tmp)
				return
			}

			tmp = strings.Trim(slice[2], "\"")

			maps["dar"] = tmp

		}

		// 查询公钥pubkey
		if strings.Contains(body, "pubkey") {

			doi = dns.Fqdn(doi)

			log.Info("receive query pub key", "doi", doi)

			qtype := dns.TypeCERT

			req := new(dns.Msg)
			req.SetQuestion(doi, qtype)
			req.SetEdns0(4096, false)
			// req.AuthenticatedData = true

			msg := handle(req)
			if msg == nil {
				// 失败：DNS解析无结果
				json, _ := json.Marshal(errmsg.ErrnoDomainResolutionError)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to handle the request", "req", req)
				return
			}

			if len(msg.Answer) == 0 {
				json, _ := json.Marshal(errmsg.ErrnoPubkeyNotFoundError)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to find the pub-key", "doi", doi)
				return
			}
			a := msg.Answer[0]

			tmp := strings.TrimPrefix(a.String(), a.Header().String())
			slice := strings.Split(tmp, " ")
			if len(slice) != 4 {

				// 失败：无法从结果RR中获取用户公钥
				json, _ := json.Marshal(errmsg.ErrnoPubkeyNotFoundError)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to split the public-key from the answer RR", "answer", tmp)
				return
			}

			var maps = make(map[string]interface{})
			maps["pubkey"] = slice[3]

		}

		// 查询数据所有者
		if strings.Contains(body, "owner") {

			doi = dns.Fqdn(doi)

			log.Info("receive query do owner", "doi", doi)

			qtype := dns.TypeRP

			req := new(dns.Msg)
			req.SetQuestion(doi, qtype)
			req.SetEdns0(4096, false)

			msg := handle(req)
			if msg == nil {
				json, _ := json.Marshal(errmsg.ErrnoDomainResolutionError)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to handle the request", "req", req)
				return
			}

			if len(msg.Answer) == 0 {

				json, _ := json.Marshal(errmsg.ErrnoOwnerNotFoundError)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to find the ownerID", "doi", doi)
				return
			}
			a := msg.Answer[0]

			tmp := strings.TrimPrefix(a.String(), a.Header().String())
			slice := strings.Split(tmp, " ")
			if len(slice) != 2 {

				json, _ := json.Marshal(errmsg.ErrnoOwnerNotFoundError)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to split the ownerID from the answer RR", "answer", tmp)
				return
			}

			tmp = strings.Trim(slice[0], "\"")

			tmp2 := strings.Split(tmp, "data")
			if len(tmp2) > 2 {
				// 失败：无法从结果全名中截取到所有者ID
				json, _ := json.Marshal(errmsg.ErrnoOwnerNotFoundError)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to split the ownerID from the whole name", "answer", tmp)
				return
			}

			maps["owner"] = tmp2[0]

		}

		// 查询权属auth
		if strings.Contains(body, "auth") {

			doi = dns.Fqdn(doi)

			// 获取权属对象doi
			dudoi := r.URL.Query().Get("dudoi")
			if dudoi == "" {
				// 失败：无法从路径query参数中获取dudoi
				json, _ := json.Marshal(errmsg.ErrnoDudoiParamsError)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to get dudoi", "url", r.URL.String())
				return
			}

			log.Info("receive query auth info", "doi", doi, "dudoi", dudoi)

			// 对dudoi哈希
			// TODO: 检查hash是否正确
			hash := Hash([]byte(dudoi))

			request := string(hash) + "." + doi

			qtype := dns.TypeTXT

			req := new(dns.Msg)
			req.SetQuestion(request, qtype)
			req.SetEdns0(4096, false)

			// req.AuthenticatedData = true

			msg := handle(req)
			if msg == nil {
				// 失败：DNS解析无结果
				json, _ := json.Marshal(errmsg.ErrnoDomainResolutionError)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to handle the request", "req", req)
				return
			}

			if len(msg.Answer) == 0 {
				// 失败：授权TXT记录不存在
				json, _ := json.Marshal(errmsg.ErrnoAuthNotFoundError)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to find the authorization info TXT", "request", request)
				return
			}
			a := msg.Answer[0]

			tmp := strings.TrimPrefix(a.String(), a.Header().String())
			if tmp == "" {
				// 失败：无法从结果RR中获取数据授权信息TXT记录
				json, _ := json.Marshal(errmsg.ErrnoAuthNotFoundError)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to split the data TXT from the answer RR", "answer", tmp)
				return
			}

			maps["auth"] = tmp

		}

		// 查询数据摘要digest
		if strings.Contains(body, "digest") {

			doi = dns.Fqdn(doi)

			qtype := dns.TypeTXT

			req := new(dns.Msg)
			req.SetQuestion(doi, qtype)
			req.SetEdns0(4096, false)

			msg := handle(req)
			if msg == nil {
				// 失败：DNS解析无结果
				json, _ := json.Marshal(errmsg.ErrnoDomainResolutionError)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to handle the request", "req", req)
				return
			}

			// log.Info("msg", msg.String())
			// log.Info("len", len(msg.Answer))

			if len(msg.Answer) == 0 {
				// 失败：数据摘要TXT记录不存在
				json, _ := json.Marshal(errmsg.ErrnoDigestNotFoundError)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to find the data digesat TXT", "dataid")
				return
			}
			// a := msg.Answer[0]

			tmp := ""
			for _, rr := range msg.Answer {
				record, isType := rr.(*dns.TXT)
				if isType {
					// logger.Get().Infof("%v", record.Txt[0])

					for _, slice := range record.Txt {
						tmp = tmp + slice
					}
				}
			}

			// tmp := strings.TrimPrefix(a.String(), a.Header().String())
			if tmp == "" {
				// 失败：无法从结果RR中获取数据摘要TXT记录
				json, _ := json.Marshal(errmsg.ErrnoDigestNotFoundError)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to split the data TXT from the answer RR", "answer", tmp)
				return
			}

			maps["digest"] = tmp

		}

		// 查询数据分类分级
		if strings.Contains(body, "classgrade") {

			doi = dns.Fqdn(doi)

			qtype := dns.TypeTXT

			// 查询分级grade
			req := new(dns.Msg)
			req.SetQuestion("_grading."+doi, qtype)
			req.SetEdns0(4096, false)

			msg := handle(req)
			if msg == nil {
				// 失败：DNS解析无结果
				json, _ := json.Marshal(errmsg.ErrnoDomainResolutionError)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to handle the request", "req", req)
				return
			}

			// log.Info("msg", msg.String())
			// log.Info("len", len(msg.Answer))

			if len(msg.Answer) == 0 {
				// 失败：数据分级TXT记录不存在
				json, _ := json.Marshal(errmsg.ErrnoGradeNotFoundError)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to find the data grade", "doi", doi)
				return
			}
			// a := msg.Answer[0]

			tmp := ""
			for _, rr := range msg.Answer {
				record, isType := rr.(*dns.TXT)
				if isType {
					// logger.Get().Infof("%v", record.Txt[0])

					for _, slice := range record.Txt {
						tmp = tmp + slice
					}
				}
			}

			if tmp == "" {
				// 失败：无法从结果RR中获取数据分级TXT记录
				json, _ := json.Marshal(errmsg.ErrnoGradeNotFoundError)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to split the grade TXT from the answer RR", "answer", tmp)
				return
			}

			maps["digest"] = tmp

			// 查询class
			req = new(dns.Msg)
			req.SetQuestion("_classification."+doi, qtype)
			req.SetEdns0(4096, false)

			msg = handle(req)
			if msg == nil {
				// 失败：DNS解析无结果
				json, _ := json.Marshal(errmsg.ErrnoDomainResolutionError)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(json)

				log.Info("failed to handle the request", "req", req)
				return
			}

			// log.Info("msg", msg.String())
			// log.Info("len", len(msg.Answer))

			if len(msg.Answer) == 0 {
				// 失败：数据分类TXT记录不存在
				json, _ := json.Marshal(errmsg.ErrnoClassNotFoundError)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to find the data classification TXT", "doi", doi)
				return
			}
			// a := msg.Answer[0]

			tmp = ""
			for _, rr := range msg.Answer {
				record, isType := rr.(*dns.TXT)
				if isType {
					// logger.Get().Infof("%v", record.Txt[0])

					for _, slice := range record.Txt {
						tmp = tmp + slice
					}
				}
			}

			if tmp == "" {
				// 失败：无法从结果RR中获取数据分类TXT记录
				json, _ := json.Marshal(errmsg.ErrnoClassNotFoundError)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(json)

				log.Info("failed to split the data class TXT from the answer RR", "answer", tmp)
				return
			}

			maps["class"] = tmp

		}

		// 查询内容为空
		if len(maps) == 0 {
			// Message: "失败：路径错误，没有有效查询",
			json, _ := json.Marshal(errmsg.ErrnoTypeParamsError)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(json)

			return

		} else {
			// 成功，返回map
			json, err := json.Marshal(errmsg.OK.WithData(maps))
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			_, _ = w.Write(json)

		}

	}
}
