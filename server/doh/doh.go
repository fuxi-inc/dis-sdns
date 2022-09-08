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
		req.AuthenticatedData = true

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

// HandleDIS handle dis request
func HandleDIS(handle func(*dns.Msg) *dns.Msg) func(http.ResponseWriter, *http.Request) {
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
			req.AuthenticatedData = true

			log.Info("request", req.Question[0].String())

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

			dataAddress := &DataAddressMsg{
				DataAddress: slice[2],
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
			req.AuthenticatedData = true

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
			req.AuthenticatedData = true

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
				log.Info("failed to split the dpodAddress from the answer RR", "answer", tmp)
				return
			}

			podAddress := &PodAddressMsg{
				PodAddress: slice[2],
			}

			json, err := json.Marshal(podAddress)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Server", "SDNS")
			w.Header().Set("Content-Type", "application/dns-json")

			_, _ = w.Write(json)

		}

	}
}
