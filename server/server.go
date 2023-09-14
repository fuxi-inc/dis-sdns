package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	l "log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/dnsutil"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/semihalev/sdns/response"
	"github.com/semihalev/sdns/server/doh"
)

// var srv ChainService

// Server type
type Server struct {
	addr           string
	tlsAddr        string
	dohAddr        string
	tlsCertificate string
	tlsPrivateKey  string

	chainPool sync.Pool

	now func() time.Time

	service ChainService
}

// New return new server
func New(cfg *config.Config) *Server {
	if cfg.Bind == "" {
		cfg.Bind = ":53"
	}

	server := &Server{
		addr:           cfg.Bind,
		tlsAddr:        cfg.BindTLS,
		dohAddr:        cfg.BindDOH,
		tlsCertificate: cfg.TLSCertificate,
		tlsPrivateKey:  cfg.TLSPrivateKey,
		now:            time.Now,
	}

	server.chainPool.New = func() interface{} {
		return middleware.NewChain(middleware.Handlers())
	}

	return server
}

// ServeDNS implements the Handle interface.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {

	// log.Info("receive dns msg", "msg", r.String())

	if fabCon {
		// 查询区块链
		q := r.Question[0]

		// 构造fabric key
		question := Question{
			Name:   q.Name,
			Qtype:  q.Qtype,
			Qclass: q.Qclass,
		}
		questionJSON, err := json.Marshal(question)
		if err != nil {
			return
		}

		i_new := new(FabricItem)
		found := false
		now := s.now().UTC()

		log.Info("fabric cache receive a dns msg", "qname", q.Name, "qtype", q.Qtype, "question", string(questionJSON))

		// 调用queryRR合约查询资源记录
		result, err := s.service.Call("queryRR", string(questionJSON))
		if err == nil {

			err = json.Unmarshal(result, i_new)
			if err != nil {
				log.Error("failed to unmarshal", "error", err.Error())
			}
			found = true

			ttl := i_new.newttl(now)

			log.Info("successfully get and transform result from fabric cache", "question", string(questionJSON), "remainTTL", ttl, "item", i_new)

			// 判断validation是否有效
			if !i_new.Validation {
				found = false
				log.Info("RR from the fabric cache has not been validated", "question", string(questionJSON))
			}

			// 判断TTL是否到期
			if ttl <= 0 {
				found = false
				log.Info("RR from the fabric cache expired in TTL", "remainTTL", ttl)
			}

		} else {
			// fabric cache上未查到
			log.Info("failed to find the RR from the fabric cache. ", "question", string(questionJSON), "error", err.Error())
		}

		// 在fabric cache中找到, reply to client
		if found {
			i := transItem(i_new)
			m := i.toMsg(r, now)

			_ = w.WriteMsg(m)
			return
		}
	}

	// // TODO: 测试编码中文域名
	// punycode, err := idna.ToASCII(r.Question[0].Name)
	// if err != nil {
	// 	log.Info("Punycode encoding error:", "name", r.Question[0].Name, "error", err.Error())
	// 	return
	// }

	// fmt.Println("test-Punycode:", punycode)

	// r.Question[0].Name = punycode

	ch := s.chainPool.Get().(*middleware.Chain)

	ch.Reset(w, r)

	ch.Next(context.Background())

	s.chainPool.Put(ch)

	// log.Info("dns response msg", "res", w.Msg())
	res := w.Msg()

	mt, _ := response.Typify(res, s.now().UTC())

	msgTTL := dnsutil.MinimalTTL(res, mt)
	duration := computeTTL(msgTTL, dnsutil.MinimalDefaultTTL, dnsutil.MaximumDefaulTTL)

	if fabCon && duration >= 30 {
		q := res.Question[0]

		go func() {
			// 构造fabric key
			question := Question{
				Name:   q.Name,
				Qtype:  q.Qtype,
				Qclass: q.Qclass,
			}
			questionJSON, err := json.Marshal(question)
			if err != nil {
				return
			}

			if duration > 0 {
				i := newItem(res, s.now(), duration, 0)
				i_new := transToFabricItem(i)

				i_new.setRR(string(questionJSON), s.service)

				fmt.Println("successfully submit CreateRR to fabric cache", "key: ", string(questionJSON), "item: ", i_new)
			}

		}()

	}

}

func (i *FabricItem) setRR(key string, srv ChainService) {
	itemAsBytes, err := json.Marshal(i)
	if err != nil {
		log.Error("failed to set RR in fabric cache : failed to marshal", "error", err.Error())
	}

	_, err = srv.SendTransaction("CreateRR", key, string(itemAsBytes), strconv.Itoa(chainConfig.Validation_account))
	if err != nil {
		log.Info("failed to submit CreateRR transaction to fabric ")
	}

}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handle := func(req *dns.Msg) *dns.Msg {
		mw := mock.NewWriter("tcp", r.RemoteAddr)
		s.ServeDNS(mw, req)

		if !mw.Written() {
			return nil
		}

		return mw.Msg()
	}

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var handlerFn func(http.ResponseWriter, *http.Request)

	log.Info("URL Path", r.URL.Path)

	if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "DataObject") {
		handlerFn = doh.HandleDISQuery(handle)
	} else if r.Method == http.MethodGet && r.URL.Query().Get("dns") == "" {
		handlerFn = doh.HandleJSON(handle)
	} else {
		handlerFn = doh.HandleWireFormat(handle)
	}

	handlerFn(w, r)
}

// Run listen the services
func (s *Server) Run() {
	go s.ListenAndServeDNS("udp")
	go s.ListenAndServeDNS("tcp")
	go s.ListenAndServeDNSTLS()
	go s.ListenAndServeHTTP()
}

// ListenAndServeDNS Starts a server on address and network specified Invoke handler
// for incoming queries.
func (s *Server) ListenAndServeDNS(network string) {
	log.Info("DNS server listening...", "net", network, "addr", s.addr)

	if network == "udp" {
		srv, err := NewChainService(ChainTypeFabric, "")
		if srv == nil || err != nil {
			log.Info("cannot connect fabric contract, use traditional cache instead")
			fabCon = false
		} else {
			log.Info("cache successfully connect to fabric contract")
		}
		s.service = srv
	}

	server := &dns.Server{
		Addr:          s.addr,
		Net:           network,
		Handler:       s,
		MaxTCPQueries: 2048,
		ReusePort:     true,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Error("DNS listener failed", "net", network, "addr", s.addr, "error", err.Error())
	}
}

// ListenAndServeDNSTLS acts like http.ListenAndServeTLS
func (s *Server) ListenAndServeDNSTLS() {
	if s.tlsAddr == "" {
		return
	}

	log.Info("DNS server listening...", "net", "tcp-tls", "addr", s.tlsAddr)

	if err := dns.ListenAndServeTLS(s.tlsAddr, s.tlsCertificate, s.tlsPrivateKey, s); err != nil {
		log.Error("DNS listener failed", "net", "tcp-tls", "addr", s.tlsAddr, "error", err.Error())
	}
}

// ListenAndServeHTTPTLS acts like http.ListenAndServeTLS
func (s *Server) ListenAndServeHTTP() {
	if s.dohAddr == "" {
		return
	}

	log.Info("DNS server listening...", "net", "http", "addr", s.dohAddr)

	logReader, logWriter := io.Pipe()
	go readlogs(logReader)

	srv := &http.Server{
		Addr:         s.dohAddr,
		Handler:      s,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		ErrorLog:     l.New(logWriter, "", 0),
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Error("DNSs listener failed", "net", "http", "addr", s.dohAddr, "error", err.Error())
	}
}

func readlogs(rd io.Reader) {
	buf := bufio.NewReader(rd)
	for {
		line, err := buf.ReadBytes('\n')
		if err != nil {
			continue
		}

		parts := strings.SplitN(string(line[:len(line)-1]), " ", 2)
		if len(parts) > 1 {
			log.Warn("Client http socket failed", "net", "https", "error", parts[1])
		}
	}
}
