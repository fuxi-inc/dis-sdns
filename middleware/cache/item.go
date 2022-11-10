// Copyright 2016-2020 The CoreDNS authors and contributors
// Adapted for SDNS usage by Semih Alev.

package cache

import (
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"golang.org/x/time/rate"
)

// RR struct
type RR struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  uint32 `json:"TTL"`
	Data string `json:"data"`
}

// FabricItem descibes basic details of a dns resource record (modify sdns/cache)
type FabricItem struct {
	Rcode              int  `json:"rcode"`
	Authoritative      bool `json:"authoritative"`
	AuthenticatedData  bool `json:"authenticated"`
	RecursionAvailable bool `json:"recursion"`
	Answer             []RR `json:"answer"`
	Ns                 []RR `json:"ns"`
	Extra              []RR `json:"extra"`

	Limiter *rate.Limiter `json:"limiter"`

	OrigTTL uint32    `json:"originTTL"`
	Stored  time.Time `json:"stored"`
}

type item struct {
	Rcode              int
	Authoritative      bool
	AuthenticatedData  bool
	RecursionAvailable bool
	Answer             []dns.RR
	Ns                 []dns.RR
	Extra              []dns.RR

	Limiter *rate.Limiter

	origTTL uint32
	stored  time.Time
}

func newItem(m *dns.Msg, now time.Time, d time.Duration, queryRate int) *item {
	i := new(item)
	i.Rcode = m.Rcode
	i.Authoritative = m.Authoritative
	i.AuthenticatedData = m.AuthenticatedData
	i.RecursionAvailable = m.RecursionAvailable
	i.Answer = m.Answer
	i.Ns = m.Ns
	i.Extra = make([]dns.RR, len(m.Extra))
	// Don't copy OPT records as these are hop-by-hop.
	j := 0
	for _, e := range m.Extra {
		if e.Header().Rrtype == dns.TypeOPT {
			continue
		}
		i.Extra[j] = e
		j++
	}
	i.Extra = i.Extra[:j]

	i.origTTL = uint32(d.Seconds())
	i.stored = now.UTC()

	limit := rate.Limit(0)
	if queryRate > 0 {
		limit = rate.Every(time.Second / time.Duration(queryRate))
	}

	i.Limiter = rate.NewLimiter(limit, queryRate)

	return i
}

func transItem(i_new *FabricItem) *item {
	if i_new == nil {
		return nil
	}

	i := &item{
		Rcode:              i_new.Rcode,
		Authoritative:      i_new.Authoritative,
		AuthenticatedData:  i_new.AuthenticatedData,
		RecursionAvailable: i_new.RecursionAvailable,
		Answer:             make([]dns.RR, len(i_new.Answer)),
		Ns:                 make([]dns.RR, len(i_new.Ns)),
		Extra:              make([]dns.RR, len(i_new.Extra)),
		Limiter:            i_new.Limiter,
		origTTL:            i_new.OrigTTL,
		stored:             i_new.Stored,
	}

	var err error
	for j, a := range i_new.Answer {
		i.Answer[j], err = dns.NewRR(a.Name + " " + strconv.FormatUint(uint64(a.TTL), 10) + " " + dns.TypeToString[a.Type] + " " + a.Data)
		if err != nil {
			log.Error("failed to create new Answer RR", "rr", a, "error", err.Error())
		}
	}

	for j, a := range i_new.Ns {
		i.Ns[j], err = dns.NewRR(a.Name + " " + strconv.FormatUint(uint64(a.TTL), 10) + " " + dns.TypeToString[a.Type] + " " + a.Data)
		if err != nil {
			log.Error("failed to create new Ns RR", "rr", a, "error", err.Error())
		}
	}

	for j, a := range i_new.Extra {
		i.Extra[j], err = dns.NewRR(a.Name + " " + strconv.FormatUint(uint64(a.TTL), 10) + " " + dns.TypeToString[a.Type] + " " + a.Data)
		if err != nil {
			log.Error("failed to create new Extra RR", "rr", a, "error", err.Error())
		}
	}

	return i

}

// toMsg turns i into a message, it tailors the reply to m.
// The Authoritative bit is always set to 0, because the answer is from the cache.
func (i *item) toMsg(m *dns.Msg, now time.Time) *dns.Msg {
	m1 := new(dns.Msg)
	m1.SetReply(m)

	m1.Authoritative = false
	m1.AuthenticatedData = i.AuthenticatedData
	m1.RecursionAvailable = i.RecursionAvailable
	m1.Rcode = i.Rcode

	m1.Answer = i.Answer
	m1.Ns = i.Ns
	m1.Extra = i.Extra

	m1.Answer = make([]dns.RR, len(i.Answer))
	m1.Ns = make([]dns.RR, len(i.Ns))
	m1.Extra = make([]dns.RR, len(i.Extra))

	ttl := uint32(i.ttl(now))
	for j, r := range i.Answer {
		m1.Answer[j] = dns.Copy(r)
		m1.Answer[j].Header().Ttl = ttl
	}
	for j, r := range i.Ns {
		m1.Ns[j] = dns.Copy(r)
		m1.Ns[j].Header().Ttl = ttl
	}
	// newItem skips OPT records, so we can just use i.Extra as is.
	for j, r := range i.Extra {
		m1.Extra[j] = dns.Copy(r)
		m1.Extra[j].Header().Ttl = ttl
	}
	return m1
}

func (i *item) ttl(now time.Time) int {
	ttl := int(i.origTTL) - int(now.UTC().Sub(i.stored).Seconds())
	return ttl
}

func transToFabricItem(i *item) *FabricItem {
	if i == nil {
		return nil
	}

	fabricItem := &FabricItem{
		Rcode:              i.Rcode,
		Authoritative:      i.Authoritative,
		AuthenticatedData:  i.AuthenticatedData,
		RecursionAvailable: i.RecursionAvailable,
		Answer:             make([]RR, len(i.Answer)),
		Ns:                 make([]RR, len(i.Ns)),
		Extra:              make([]RR, len(i.Extra)),
		Limiter:            i.Limiter,
		OrigTTL:            i.origTTL,
		Stored:             i.stored,
	}

	for i, a := range i.Answer {
		fabricItem.Answer[i] = RR{
			Name: a.Header().Name,
			Type: a.Header().Rrtype,
			TTL:  a.Header().Ttl,
			Data: strings.TrimPrefix(a.String(), a.Header().String()),
		}
	}

	for i, a := range i.Ns {
		fabricItem.Ns[i] = RR{
			Name: a.Header().Name,
			Type: a.Header().Rrtype,
			TTL:  a.Header().Ttl,
			Data: strings.TrimPrefix(a.String(), a.Header().String()),
		}
	}

	for i, a := range i.Extra {
		fabricItem.Extra[i] = RR{
			Name: a.Header().Name,
			Type: a.Header().Rrtype,
			TTL:  a.Header().Ttl,
			Data: strings.TrimPrefix(a.String(), a.Header().String()),
		}
	}

	return fabricItem
}
