package errmsg

import "net/http"

var codeMsg = map[int]string{
	http.StatusOK:                  "操作成功",
	http.StatusCreated:             "创建成功",
	http.StatusBadRequest:          "参数错误",
	http.StatusUnauthorized:        "签名验证失败",
	http.StatusNotFound:            "记录不存在",
	http.StatusForbidden:           "权限错误，g",
	http.StatusInternalServerError: "服务器错误",
}

func GetErrMsg(code int) string {
	return codeMsg[code]
}
