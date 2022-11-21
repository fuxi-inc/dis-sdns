package cache

import (
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

	sdnsCfg "github.com/fuxi-inc/dis-sdns/config"
)

const (
	DefaultProfile = "dev"
	ConfigFile     = "connection.yaml"
)

var fabCon = false
var contract *gateway.Contract
var currentProfile string

var chainConfig sdnsCfg.ChainCfg

// fabric key for RR
type Question struct {
	Name   string `json:"name"`
	Qtype  uint16 `json:"qtype"`
	Qclass uint16 `json:"qclass"`
}

// fabric createRR event
type Event struct {
	Key  string `json:"key"`
	Item string `json:"item"`
}

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

	fabCon = chainConfig.FabCon

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

	// register identity
	_, err = contract.SubmitTransaction("CreateID")
	if err != nil {
		log.Error("failed to submit CreateID transaction to fabric ", "error", err.Error())
		return nil
	}

	// register fabric CreateRR event
	_, notifier, err := contract.RegisterEvent("CreateRR")
	if err != nil {
		fmt.Printf("Failed to register contract event: %s", err)
		return nil
	}
	// defer contract.Unregister(reg)

	// consume event and vote for validation
	go func() {
		for e := range notifier {
			fmt.Printf("Receive cc event, ccid: %v \neventName: %v\n"+
				"payload: %v \ntxid: %v \nblock: %v \nsourceURL: %v\n",
				e.ChaincodeID, e.EventName, string(e.Payload), e.TxID, e.BlockNumber, e.SourceURL)

			event := new(Event)
			err := json.Unmarshal(e.Payload, event)
			if err != nil {
				log.Error("failed to unmarshal", "event", string(e.Payload), "error", err.Error())
				continue
			}

			itemAsBytes := []byte(event.Item)

			fabricItem := new(FabricItem)
			err = json.Unmarshal(itemAsBytes, fabricItem)
			if err != nil {
				log.Error("failed to unmarshal", "fabricitem", string(itemAsBytes), "error", err.Error())
				continue
			}

			if fabricItem.Validation {
				// no validation required
				log.Info("no validation required", "key", event.Key)
				continue
			}

			// TODO: 验证记录的正确性，决定投票结果
			// ......
			validation := true

			if validation {
				_, err = contract.SubmitTransaction("VoteTrue", event.Key)
				if err != nil {
					log.Error("failed to submit VoteTrue transaction to fabric", "error", err.Error())
					continue
				}

				log.Info("Submit VoteTrue transaction to fabric", "key", event.Key)
			} else {
				log.Info("did not vote for true", "key", event.Key)
				// TODO: 投反对票?
			}

		}
	}()

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
