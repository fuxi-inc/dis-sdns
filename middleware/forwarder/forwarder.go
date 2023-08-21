package forwarder

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/dnsutil"
	"github.com/semihalev/sdns/middleware"
)

// Forwarder type
type Forwarder struct {
	servers []string
}

func init() {
	middleware.Register(name, func(cfg *config.Config) middleware.Handler {
		return New(cfg)
	})
}

// New return forwarder
func New(cfg *config.Config) *Forwarder {
	forwarderservers := []string{}
	for _, s := range cfg.ForwarderServers {
		host, _, _ := net.SplitHostPort(s)

		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
			forwarderservers = append(forwarderservers, s)
		} else if ip != nil && ip.To16() != nil {
			forwarderservers = append(forwarderservers, s)
		} else {
			log.Error("Forwarder server is not correct. Check your config.", "server", s)
		}
	}

	return &Forwarder{servers: forwarderservers}
}

// Name return middleware name
func (f *Forwarder) Name() string { return name }

// ServeDNS implements the Handle interface.
func (f *Forwarder) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	if len(req.Question) == 0 || len(f.servers) == 0 {
		ch.CancelWithRcode(dns.RcodeServerFailure, true)
	}

	fReq := new(dns.Msg)
	fReq.SetQuestion(req.Question[0].Name, req.Question[0].Qtype)
	fReq.SetEdns0(dnsutil.DefaultMsgSize, true)
	fReq.RecursionDesired = true
	fReq.CheckingDisabled = req.CheckingDisabled

	for _, server := range f.servers {

		// 230810临时方案：轮询查询，确保内容同步成功
		// last := ""

		start := time.Now()

		flag := false

		for {

			log.Info("receive req query", "req", req.String())
			resp, err := dns.Exchange(req, server)
			// log.Info("req", req.String())
			log.Info("get resp from the forwarder", "resp", resp.String())

			q := req.Question[0]

			if err != nil {
				log.Warn("forwarder query failed", "query", formatQuestion(req.Question[0]), "error", err.Error())
				flag = true
				break
			}

			resp.Id = req.Id

			if !req.Zero || q.Qtype != dns.TypeCERT {
				_ = w.WriteMsg(resp)
				break
			}

			// check if 10 seconds have passed
			if time.Since(start).Seconds() > 10 {
				_ = w.WriteMsg(resp)
				break
			}

			if len(resp.Answer) != 0 {
				_ = w.WriteMsg(resp)
				break

			}

			// 没有查到内容，一直轮询
			time.Sleep(time.Millisecond * 500)

			log.Info("start round query")

			// a := resp.Answer[0]

			// tmp := strings.TrimPrefix(a.String(), a.Header().String())

			// if last != "" && tmp != last {
			// 	// 检测到内容更新
			// 	_ = w.WriteMsg(resp)
			// 	break
			// }
			// last = tmp

		}

		if flag {
			continue
		}

		return
	}

	ch.CancelWithRcode(dns.RcodeServerFailure, true)
}

func formatQuestion(q dns.Question) string {
	return strings.ToLower(q.Name) + " " + dns.ClassToString[q.Qclass] + " " + dns.TypeToString[q.Qtype]
}

const name = "forwarder"
