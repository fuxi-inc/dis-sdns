package errmsg

import "net/http"

var codeMsg = map[int]string{
	http.StatusOK:                  "操作成功",
	http.StatusCreated:             "创建成功",
	http.StatusBadRequest:          "参数错误",
	http.StatusUnauthorized:        "签名验证失败",
	http.StatusNotFound:            "身份标识或数据标识不存在",
	http.StatusForbidden:           "权限错误，当前用户无权限操作",
	http.StatusInternalServerError: "服务器错误",
}

func GetErrMsg(code int) string {
	return codeMsg[code]
}
