package errmsg

import (
	"encoding/json"
)

var _ Error = (*err)(nil)

type Error interface {
	// WithData 设置成功时返回的数据
	WithData(data interface{}) Error
	// ToString 返回 JSON 格式的错误详情
	ToString() string
}

type err struct {
	Code int64       `json:"code"` // 业务编码
	Data interface{} `json:"data"` // 成功时返回的数据
	Msg  string      `json:"msg"`  // 错误描述
}

func NewError(code int64, msg string) Error {
	return &err{
		Code: code,
		Data: nil,
		Msg:  msg,
	}
}

func (e *err) WithData(data interface{}) Error {
	e.Data = data
	return e
}

// ToString 返回 JSON 格式的错误详情
func (e *err) ToString() string {
	err := &struct {
		Code int64       `json:"code"`
		Data interface{} `json:"data"`
		Msg  string      `json:"msg"`
	}{
		Code: e.Code,
		Data: e.Data,
		Msg:  e.Msg,
	}

	raw, _ := json.Marshal(err)
	return string(raw)
}
