package cache

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
	"github.com/semihalev/log"
	"github.com/spf13/viper"

	sdnsCfg "github.com/semihalev/sdns/config"
)

const (
	DefaultProfile = "dev"
	ConfigFile     = "connection.yaml"
)

var fabCon = true
var contract *gateway.Contract
var currentProfile string

var chainConfig sdnsCfg.ChainCfg

// var credPath = filepath.Join(
// 	"/home",
// 	"fuxi",
// 	"fabric-samples",
// 	"test-network",
// 	"organizations",
// 	"peerOrganizations",
// 	"org1.example.com",
// 	"users",
// 	"User1@org1.example.com",
// 	"msp",
// )

// var ccpPath = filepath.Join(
// 	"/home",
// 	"fuxi",
// 	"fabric-samples",
// 	"test-network",
// 	"organizations",
// 	"peerOrganizations",
// 	"org1.example.com",
// 	"connection-org1.yaml",
// )

func ReadChainCfg() sdnsCfg.ChainCfg {
	v := viper.New()

	currentProfile = os.Getenv("APP_PROFILE")
	if currentProfile == "" {
		currentProfile = DefaultProfile
	}

	v.AutomaticEnv()
	v.SetConfigName("application")
	v.AddConfigPath(filepath.Join("config", currentProfile))
	err := v.ReadInConfig()
	if err != nil {
		log.Crit("failed to load chain config file", "error", err.Error())
	}

	err = v.Unmarshal(&chainConfig)
	if err != nil {
		log.Crit("failed to unmarshal chain config", "error", err.Error())
	}

	return chainConfig
}

// 连接Fabric，返回*gateway.Contract
func ConnectFab() *gateway.Contract {

	os.Setenv("DISCOVERY_AS_LOCALHOST", "true")

	chainConfig = ReadChainCfg()

	wallet, err := gateway.NewFileSystemWallet("wallet")
	if err != nil {
		log.Error("failed to create wallet", "error", err.Error())
		return nil
	}

	if !wallet.Exists(chainConfig.UserName) {
		err = populateWallet(wallet)
		if err != nil {
			log.Error("failed to populate wallet contents", "error", err.Error())
			return nil
		}
	}

	ccpPath := chainConfig.ConPath

	gw, err := gateway.Connect(
		gateway.WithConfig(config.FromFile(filepath.Clean(ccpPath))),
		gateway.WithIdentity(wallet, chainConfig.UserName),
	)
	if err != nil {
		log.Error("failed to connect to gateway", "error", err.Error())
		return nil
	}

	log.Info("channel", chainConfig.Channel)
	network, err := gw.GetNetwork(chainConfig.Channel)
	if err != nil {
		log.Error("failed to get network", "error", err.Error())
		return nil
	}

	contract := network.GetContract(chainConfig.ChaincodeDIS)

	_, notifier, err := contract.RegisterEvent("CreateRR")
	if err != nil {
		fmt.Printf("Failed to register contract event: %s", err)
		return nil
	}
	// defer contract.Unregister(reg)

	// consume event
	go func() {
		fmt.Printf("------")
		for e := range notifier {
			fmt.Printf("Receive cc event, ccid: %v \neventName: %v\n"+
				"payload: %v \ntxid: %v \nblock: %v \nsourceURL: %v\n",
				e.ChaincodeID, e.EventName, string(e.Payload), e.TxID, e.BlockNumber, e.SourceURL)
		}
		fmt.Printf("++++++")
	}()

	// time.Sleep(10 * time.Second)
	// _, err = contract.SubmitTransaction("QueryRR", "4496651133470472589")
	// if err != nil {
	// 	fmt.Printf("Failed to submit transaction: %s\n", err)
	// 	return nil
	// }

	// var ccEvent *fab.CCEvent
	// select {
	// case ccEvent = <-notifier:
	// 	fmt.Printf("Received CC event: %#v\n", ccEvent)
	// case <-time.After(time.Minute * 10):
	// 	fmt.Printf("Did NOT receive CC event for eventId(%s)\n", "CreateRR")
	// }

	// // create sdk
	// sdk, err := fabsdk.New(config.FromFile(ccpPath))
	// if err != nil {
	// 	log.Error("failed to create fabric sdk", "error", err.Error())
	// 	return nil
	// }

	// // New event client
	// cp := sdk.ChannelContext(chainConfig.Channel, fabsdk.WithUser("User1"), fabsdk.WithOrg("Org1"))

	// ec, err := event.New(
	// 	cp,
	// 	event.WithBlockEvents(), // 如果没有，会是filtered
	// 	// event.WithBlockNum(1), // 从指定区块获取，需要此参数
	// 	// event.WithSeekType(seek.Newest)
	// )
	// if err != nil {
	// 	log.Error("Create event client error", "error", err.Error())
	// 	return nil
	// }

	// // Context used for event listening
	// ctx, cancel := context.WithCancel(context.Background())
	// defer cancel()

	// Listen for events emitted by subsequent transactions
	// _, eventCh, err := ec.RegisterChaincodeEvent(chainConfig.Channel, "CreateRR")
	// if err != nil {
	// 	log.Error("Failed to regitser block event", "error", err.Error())
	// 	return nil
	// }
	// defer ec.Unregister(reg)

	// consume event
	// go func() {
	// 	fmt.Printf("------")
	// 	for e := range eventCh {
	// 		fmt.Printf("Receive cc event, ccid: %v \neventName: %v\n"+
	// 			"payload: %v \ntxid: %v \nblock: %v \nsourceURL: %v\n",
	// 			e.ChaincodeID, e.EventName, string(e.Payload), e.TxID, e.BlockNumber, e.SourceURL)
	// 	}
	// 	fmt.Printf("======")
	// }()

	return contract
}

// 创建钱包用户resUser
func populateWallet(wallet *gateway.Wallet) error {

	credPath := chainConfig.MSPPath

	certPath := filepath.Join(credPath, "signcerts", "cert.pem")
	// read the certificate pem
	cert, err := ioutil.ReadFile(filepath.Clean(certPath))
	if err != nil {
		return err
	}

	keyDir := filepath.Join(credPath, "keystore")
	// there's a single file in this dir containing the private key
	files, err := ioutil.ReadDir(keyDir)
	if err != nil {
		return err
	}
	if len(files) != 1 {
		return errors.New("keystore folder should have contain one file")
	}
	keyPath := filepath.Join(keyDir, files[0].Name())
	key, err := ioutil.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return err
	}

	identity := gateway.NewX509Identity(chainConfig.MSPID, string(cert), string(key))

	err = wallet.Put(chainConfig.UserName, identity)
	if err != nil {
		return err
	}
	return nil
}

func formatJSON(data []byte) string {
	var result bytes.Buffer
	if err := json.Indent(&result, data, "", "  "); err != nil {
		panic(fmt.Errorf("failed to parse JSON: %w", err))
	}
	return result.String()
}

func (i *FabricItem) setRR(key string) {
	itemAsBytes, err := json.Marshal(i)
	if err != nil {
		log.Error("failed to set RR in fabric cache : failed to marshal", "error", err.Error())
	}

	_, err = contract.SubmitTransaction("CreateRR", key, string(itemAsBytes))
	if err != nil {
		log.Info("failed to submit CreateRR transaction to fabric ")
	}

}

// var credPath = filepath.Join(
// 	"/home",
// 	"fuxi",
// 	"dis-fabric",
// 	"data",
// 	"organizations",
// 	"org-alpha",
// 	"admin",
// 	"msp",
// )

// var ccpPath = filepath.Join(
// 	"./",
// 	"config",
// 	"connection.yaml",
// )

// // 连接Fabric，返回*gateway.Contract
// func ConnectFab() *gateway.Contract {
// 	os.Setenv("DISCOVERY_AS_LOCALHOST", "false")
// 	wallet, err := gateway.NewFileSystemWallet("wallet")
// 	if err != nil {
// 		log.Error("failed to create wallet", "error", err.Error())
// 		return nil
// 	}

// 	if !wallet.Exists("dis-resolver-admin-user") {
// 		err = populateWallet(wallet)
// 		if err != nil {
// 			log.Error("failed to populate wallet contents", "error", err.Error())
// 			return nil
// 		}
// 	}

// 	gw, err := gateway.Connect(
// 		gateway.WithConfig(config.FromFile(filepath.Clean(ccpPath))),
// 		gateway.WithIdentity(wallet, "dis-resolver-admin-user"),
// 	)
// 	if err != nil {
// 		log.Error("failed to connect to gateway", "error", err.Error())
// 		return nil
// 	}

// 	network, err := gw.GetNetwork("dis-channel")
// 	if err != nil {
// 		log.Error("failed to get network", "error", err.Error())
// 		return nil
// 	}

// 	contract := network.GetContract("dis_resolver")
// 	return contract
// }

// // 创建钱包用户resUser
// func populateWallet(wallet *gateway.Wallet) error {

// 	certPath := filepath.Join(credPath, "signcerts", "cert.pem")
// 	// read the certificate pem
// 	cert, err := ioutil.ReadFile(filepath.Clean(certPath))
// 	if err != nil {
// 		return err
// 	}

// 	keyDir := filepath.Join(credPath, "keystore")
// 	// there's a single file in this dir containing the private key
// 	files, err := ioutil.ReadDir(keyDir)
// 	if err != nil {
// 		return err
// 	}
// 	if len(files) != 1 {
// 		return errors.New("keystore folder should have contain one file")
// 	}
// 	keyPath := filepath.Join(keyDir, files[0].Name())
// 	key, err := ioutil.ReadFile(filepath.Clean(keyPath))
// 	if err != nil {
// 		return err
// 	}

// 	identity := gateway.NewX509Identity("org-alpha-msp", string(cert), string(key))

// 	err = wallet.Put("dis-resolver-admin-user", identity)
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }

// func (i *FabricItem) setRR(key string) {
// 	itemAsBytes, err := json.Marshal(i)
// 	if err != nil {
// 		log.Error("failed to set RR in fabric cache : failed to marshal", "error", err.Error())
// 	}

// 	_, err = contract.SubmitTransaction("CreateRR", key, string(itemAsBytes))
// 	if err != nil {
// 		log.Info("failed to submit CreateRR transaction to fabric ")
// 	}

// }
