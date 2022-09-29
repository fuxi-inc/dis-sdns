package doh

import (
	"strings"

	"github.com/miekg/dns"
)

// Question struct
type Question struct {
	Name   string `json:"name"`
	Qtype  uint16 `json:"type"`
	Qclass uint16 `json:"-"`
}

// RR struct
type RR struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  uint32 `json:"TTL"`
	Data string `json:"data"`
}

// Msg struct
type Msg struct {
	Status    int
	TC        bool
	RD        bool
	RA        bool
	AD        bool
	CD        bool
	Question  []Question
	Answer    []RR `json:",omitempty"`
	Authority []RR `json:",omitempty"`
}

// 标准返回
type ReturnMsg struct {
	Status  int                    `json:"code"`
	Data    map[string]interface{} `json:"data"`
	Message string                 `json:"message"`
}

// 数据地址查询返回
type DataAddressMsg struct {
	DataAddress string `json:"dataAddress"`
}

// 身份公钥查询返回
type UserKeyMsg struct {
	UserKey string `json:"userKey"`
}

// pod地址查询返回
type PodAddressMsg struct {
	PodAddress string `json:"podAddress"`
}

// 数据所有者查询返回
type OwnerMsg struct {
	OwnerID string `json:"ownerID"`
}

// 数据TXT记录查询返回
type AuthMsg struct {
	Auth string `json:"auth"`
}

// 完整性验证请求返回
type IntegrityMsg struct {
	Auth bool `json:"auth"`
}

// 授权验证查询请求
type AuthorizationParams struct {
	Identifier string `json:"dataID"`
	Recipient  string `json:"viewUserID"`
}

// 授权验证签名体
type AuthAuthoSign struct {
	Dataid string `json:"dataID"`
	Userid string `json:"userID"`
}

// 身份验证签名体
type AuthIdentitySign struct {
	ID string `json:"userid"`
}

// NewMsg function
func NewMsg(m *dns.Msg) *Msg {
	if m == nil {
		return nil
	}

	msg := &Msg{
		Status:    m.Rcode,
		TC:        m.Truncated,
		RD:        m.RecursionDesired,
		RA:        m.RecursionAvailable,
		AD:        m.AuthenticatedData,
		CD:        m.CheckingDisabled,
		Question:  make([]Question, len(m.Question)),
		Answer:    make([]RR, len(m.Answer)),
		Authority: make([]RR, len(m.Ns)),
	}

	for i, q := range m.Question {
		msg.Question[i] = Question(q)
	}

	for i, a := range m.Answer {
		msg.Answer[i] = RR{
			Name: a.Header().Name,
			Type: a.Header().Rrtype,
			TTL:  a.Header().Ttl,
			Data: strings.TrimPrefix(a.String(), a.Header().String()),
		}
	}

	for i, a := range m.Ns {
		msg.Authority[i] = RR{
			Name: a.Header().Name,
			Type: a.Header().Rrtype,
			TTL:  a.Header().Ttl,
			Data: strings.TrimPrefix(a.String(), a.Header().String()),
		}
	}

	return msg
}
