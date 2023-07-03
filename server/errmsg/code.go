package errmsg

var (
	// 操作成功错误码
	OK = NewError(0, "操作成功")

	// HTTPStatusCode 400
	ErrnoDoiParamsError   = NewError(40000, "请求参数错误-缺少doi")
	ErrnoDudoiParamsError = NewError(40000, "请求参数错误-缺少所有者doi")
	ErrnoTypeParamsError  = NewError(40000, "请求参数错误-查询type错误")

	ErrnoDomainResolutionError = NewError(30000, "DNS权威解析错误")

	ErrnoDarNotFoundError    = NewError(30001, "DO数据地址未找到")
	ErrnoPubkeyNotFoundError = NewError(30001, "DO公钥未找到")
	ErrnoOwnerNotFoundError  = NewError(30001, "DO所有者未找到")
	ErrnoAuthNotFoundError   = NewError(30001, "DO权属信息未找到")
	ErrnoDigestNotFoundError = NewError(30001, "DO数据摘要未找到")
	ErrnoGradeNotFoundError  = NewError(30001, "DO数据分级未找到")
	ErrnoClassNotFoundError  = NewError(30001, "DO数据分类未找到")
)

// var (
//     // 操作成功错误码
//     // HTTPStatusCode 200
//     OK = NewError(0, "操作成功")

//     // HTTPStatusCode 500
//     ServerError        = NewError(10001, "系统错误")
//     UserKeyImportError = NewError(10002, "用户公钥格式错误")
//     MarshalError       = NewError(10003, "marshal结构体失效")

//     // HTTPStatusCode 400
//     RequestSchemaError    = NewError(10101, "请求格式错误")                //请求body-marshal出错
//     PathError             = NewError(10102, "路径错误")                    //请求Path错误
//     ParamFormatError      = NewError(10102, "参数不符合规范")              //请求body-参数定义不符合规范
//     PathParamError        = NewError(10103, "路径参数缺失")                //请求path-参数缺失或者请求body-非空参数为空
//     DomainFormatError     = NewError(10104, "标识格式错误，不符合域名规范") //参数中标识不符合域名规范
//     DomainResolutionError = NewError(10105, "DNS权威解析失败")             // DNS权威查询无返回结果

//     SignDecodeError = NewError(10106, "签名格式错误") //签名base64解码失败

//     // AuthGetError    = NewError(10201, "身份认证信息缺失")   //请求header-authorization为空
//     // AuthFormatError = NewError(10202, "身份认证信息格式错误") //请求header-authorization对应的值格式错误

//     // HTTPStatusCode 401
//     AuthFailError = NewError(10201, "身份认证失败")

//     // HTTPStatusCode 403
//     PermissionError = NewError(10401, "权限错误") //当前操作者不具备权限操作

//     // HTTPStatusCode 404
//     DataAddressNotFoundError       = NewError(20301, "数据标识不存在")
//     PublicKeyNotFoundError         = NewError(20302, "数据标识不存在")
//     PodNotFoundError               = NewError(20303, "POD地址不存在")
//     OwnerNotFoundError             = NewError(20304, "数据所有者不存在")
//     AuthInfoNotFoundError          = NewError(20305, "授权信息不存在")
//     DataDigestNotFoundError        = NewError(20306, "数据摘要不存在")
//     DataEncryptionKeyNotFoundError = NewError(20307, "数据秘钥不存在")

//     // // 模块级错误码 - 身份模块
//     // // HTTPStatusCode 500
//     // UserKeyGetError    = NewError(20101, "用户公钥获取失败")

//     // UserExistError     = NewError(20103, "用户已存在")
//     // // HTTPStatusCode 404
//     // UserNotFoundError = NewError(20104, "用户不存在")

//     // // 模块级错误码 - Token模块
//     // // HTTPStatusCode 500
//     // TokenMinusError     = NewError(20201, "Token数目必须为正数")
//     // TokenNotEnoughError = NewError(20202, "Token不足")

//     // // 模块级错误码 - 数据标识模块
//     // // HTTPStatusCode 500
//     // DataOwnerError       = NewError(20301, "当前操作者不是数据所有者")
//     // DataOwnerUpdateError = NewError(20302, "原数据所有者和新数据所有者不能相同")
//     // DataExistError       = NewError(20303, "数据标识已存在")
//     // // HTTPStatusCode 404
//     // DataNotFoundError = NewError(20304, "数据标识不存在")

//     // // 模块级错误码 - 授权模块
//     // // HTTPStatusCode 500
//     // AuthorizationExistError    = NewError(20401, "授权已存在")
//     // AuthorizationTransferError = NewError(20402, "被动授权转账失败")
//     // AuthorizationGenError      = NewError(20403, "被动授权信息产生失败")

//     // // 模块级错误码 - 访问记录模块
//     // // HTTPStatusCode 500
//     // AccessNoAuthrzError = NewError(20501, "访问未被授权")
// )
