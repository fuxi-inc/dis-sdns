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

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
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

// var m []uint16

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

	log.Info("receive dns msg", "msg", r.String())

	// if fabCon {
	// 	// 查询区块链
	// 	q := r.Question[0]

	// 	// 构造fabric key
	// 	question := Question{
	// 		Name:   q.Name,
	// 		Qtype:  q.Qtype,
	// 		Qclass: q.Qclass,
	// 	}
	// 	questionJSON, err := json.Marshal(question)
	// 	if err != nil {
	// 		return
	// 	}

	// 	i_new := new(FabricItem)
	// 	found := false
	// 	now := s.now().UTC()

	// 	log.Info("fabric cache receive a dns msg", "qname", q.Name, "qtype", q.Qtype, "question", string(questionJSON))

	// 	// 调用queryRR合约查询资源记录
	// 	result, err := s.service.Call("queryRR", string(questionJSON))
	// 	if err == nil {

	// 		err = json.Unmarshal(result, i_new)
	// 		if err != nil {
	// 			log.Error("failed to unmarshal", "error", err.Error())
	// 		}
	// 		found = true

	// 		ttl := i_new.newttl(now)

	// 		log.Info("successfully get and transform result from fabric cache", "question", string(questionJSON), "remainTTL", ttl, "item", i_new)

	// 		// 判断validation是否有效
	// 		if !i_new.Validation {
	// 			found = false
	// 			log.Info("RR from the fabric cache has not been validated", "question", string(questionJSON))
	// 		}

	// 		// 判断TTL是否到期
	// 		if ttl <= 0 {
	// 			found = false
	// 			log.Info("RR from the fabric cache expired in TTL", "remainTTL", ttl)
	// 		}

	// 	} else {
	// 		// fabric cache上未查到
	// 		log.Info("failed to find the RR from the fabric cache. ", "question", string(questionJSON), "error", err.Error())
	// 	}

	// 	// 在fabric cache中找到, reply to client
	// 	if found {
	// 		i := transItem(i_new)
	// 		m := i.toMsg(r, now)

	// 		_ = w.WriteMsg(m)
	// 		return
	// 	}
	// }

	ch := s.chainPool.Get().(*middleware.Chain)

	ch.Reset(w, r)

	ch.Next(context.Background())

	s.chainPool.Put(ch)

	log.Info("dns response msg", "res", w.Msg())

	// -------TODO: ignore repeate msg ----
	// id := w.Msg().Id
	// for _, value := range m {
	// 	if value == id {
	// 		log.Info("repeat msg detected", "msg_id", strconv.Itoa(int(id)))
	// 		m
	// 		return
	// 	}
	// }

	res := w.Msg()
	q := res.Question[0]

	// query verification ；目前只针对A记录
	if (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA) && fabCon {

		mt, _ := response.Typify(res, s.now().UTC())

		msgTTL := dnsutil.MinimalTTL(res, mt)
		duration := computeTTL(msgTTL, dnsutil.MinimalDefaultTTL, dnsutil.MaximumDefaulTTL)

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

		i := newItem(res, s.now(), duration, 0)
		i_new := transToFabricItem(i)

		itemAsBytes, err := json.Marshal(i_new)
		if err != nil {
			log.Error("failed to set RR in fabric cache : failed to marshal", "error", err.Error())
			return
		}

		resultAsBytes, err := s.service.Call("QueryVerify", string(questionJSON), string(itemAsBytes))
		if err != nil {
			log.Warn("failed to evaluate", "question", string(questionJSON), "item", string(itemAsBytes))
		}

		result := new(verifyresult)
		err = json.Unmarshal(resultAsBytes, result)
		if err != nil {
			log.Warn("failed to unmarshal", "result", string(resultAsBytes))
			return
		}

		// if updating transaction
		if result.Result == "collision" {
			i_new.Validation = "updating"
			i_new.Update_txid = result.Update_txid
		}

		if result.Result == "verified" {
			// 验证通过， 直接返回
			// -----TODO: 添加返回信息-----
			log.Info("verified successfully", "question", string(questionJSON), "item", string(itemAsBytes))
			return
		} else {
			go func() {
				txID, err := i_new.setRR(string(questionJSON), s.service)
				if err != nil {
					return
				}

				fmt.Println("successfully submit StartValidation", "txID", txID, "key: ", string(questionJSON), "item: ", i_new)

				contract := s.service.GetContract()
				// register fabric CreateRR event
				reg, notifier, err := contract.RegisterEvent("voting " + txID)
				if err != nil {
					fmt.Printf("Failed to register contract event: %s", err)
					return
				}
				defer contract.Unregister(reg)

				var e *fab.CCEvent

				y := 0
				n := 0
				var validation bool
				var voterStr string

			Loop:
				for {
					select {
					case e = <-notifier:
						fmt.Printf("Receive voting event, ccid: %v \neventName: %v\n"+
							"payload: %v \ntxid: %v \nblock: %v \nsourceURL: %v\n",
							e.ChaincodeID, e.EventName, string(e.Payload), e.TxID, e.BlockNumber, e.SourceURL)

						event := new(votingEvent)
						err := json.Unmarshal(e.Payload, event)
						if err != nil {
							fmt.Println("failed to unmarshal")
							continue Loop
						}

						result := event.Result

						// Compute voting yes
						if result == "yes" {
							y++
							if y == chainConfig.Voters_account {
								validation = true
								voterStr = voterStr + event.VoterID + " --- "
								break Loop
							}
						} else if result == "no" {
							// Compute Voting no
							n++
							if n == chainConfig.Validators_account-chainConfig.Voters_account+1 {
								break Loop
							}
						}

					case <-time.After(time.Second * 10):
						fmt.Printf("Did NOT receive CC event for eventId(%s)\n", txID)
						break Loop
					}

				}
				fmt.Printf("finished receive voting msg\n")

				var result string
				if validation {
					result = "yes"
				} else {
					result = "no"
				}

				_, err = s.service.SendTransaction("FinishValidation", string(questionJSON), txID, result, voterStr)
				if err != nil {
					fmt.Printf("failed to submit FinishValidation txid: %s transaction to fabric: %s\n", txID, err.Error())
				} else {
					fmt.Printf("successfully submit FinishValidation transaction to fabric\n")
				}

			}()

		}

		// write

	}

}

func (i *FabricItem) setRR(key string, srv ChainService) (string, error) {
	itemAsBytes, err := json.Marshal(i)
	if err != nil {
		log.Error("failed to set RR in fabric cache : failed to marshal", "error", err.Error())
		return "", err
	}

	txID, err := srv.SendTransaction("StartValidation", key, string(itemAsBytes), strconv.Itoa(chainConfig.Validators_account), strconv.Itoa(chainConfig.Voters_account))
	if err != nil {
		log.Info("failed to submit StartValidation transaction to fabric ", "error", err.Error())
		return "", err
	}

	return string(txID), nil
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

	var handlerFn func(http.ResponseWriter, *http.Request)

	// log.Info("URL Path", r.URL.Path)
	if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "dis-query") {
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
	// go s.ListenAndServeDNS("tcp")
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
