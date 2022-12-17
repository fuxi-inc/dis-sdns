package server

import "errors"

type ChainService interface {
	//获取区块链类型
	getType() string

	//调用合约（读）
	Call(name string, args ...string) ([]byte, error)

	//发送交易（写）
	SendTransaction(name string, args ...string) ([]byte, error)

	//加载配置文件
	LoadConfig(confs ...string) error
}

const ChainTypeFabric = "Fabric"

/*
函数功能：

	通过输入区块链类型、配置文件（若干），获取一个区块链服务对象

参数：

	chaintype: 区块链类型；e.g. "Fabric"
	confs: 配置文件（若干）；e.g. "application.yaml", "connection.yaml"

返回值：

	一个 ChainService 对象
*/
func NewChainService(chaintype string, confs ...string) (ChainService, error) {
	var srv ChainService
	if chaintype == ChainTypeFabric {
		srv = new(FabricService)
		err := srv.LoadConfig(confs...)
		return srv, err
	}
	return nil, errors.New("no chain service")
}
