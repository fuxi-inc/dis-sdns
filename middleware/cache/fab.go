package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/dnsutil"
	"github.com/spf13/viper"

	sdnsOldCfg "github.com/semihalev/sdns/config"

	sdnsCfg "github.com/fuxi-inc/dis-sdns/config"
)

const (
	DefaultProfile = "dev"
	ConfigFile     = "connection.yaml"
)

var fabCon = false
var contract *gateway.Contract
var currentProfile string
var clientID []byte

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
	clientID, err = contract.SubmitTransaction("CreateID")
	if err != nil {
		log.Error("failed to submit CreateID transaction to fabric ", "error", err.Error())
		return nil
	}
	log.Info("successfully register ID", "clientID", string(clientID))

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

			if fabricItem.CreatorID == string(clientID) {
				log.Info("Creator == ClientID, don't validate", "clientID", string(clientID))
				continue
			}

			fmt.Println("++++++++")

			if fabricItem.Validation {
				// no validation required
				log.Info("no validation required", "key", event.Key)
				continue
			}

			// 验证记录的正确性，决定投票结果
			validation := false
			q := new(Question)
			err = json.Unmarshal([]byte(event.Key), q)
			if err != nil {
				log.Error("failed to unmarshal", "quastion", event.Key, "error", err.Error())
				continue
			}

			name := dns.Fqdn(q.Name)
			split := dns.SplitDomainName(name)

			fmt.Println("==============")

			// 检索fuxi域，直接通过forwarder
			if len(split) > 0 && split[len(split)-1] == "fuxi" {
				validation = true

				fmt.Println("000000000000")

			} else {
				ctx := context.Background()

				req := new(dns.Msg)
				req.SetQuestion(q.Name, q.Qtype)
				req.SetEdns0(dnsutil.DefaultMsgSize, true)

				cfg := makeValidationConfig()
				r := NewResolver(cfg)

				fmt.Println("----------------")
				resp, err := r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)
				if err != nil {
					log.Info("Resolve query failed", "query name", q.Name, "error", err.Error())
					continue
				}

				fmt.Printf("response from validation resolve request: %s\n", resp.String())
				fmt.Println("]]]]]]]]]]]]]")

				// TODO: 比较resp和fabricItem
				validation = true

			}

			if validation {

				_, err = contract.SubmitTransaction("VoteTrue", event.Key)
				if err != nil {
					// log.Error("failed to submit VoteTrue transaction to fabric", "error", err.Error())
					fmt.Printf("failed to submit VoteTrue transaction to fabric: %s", err.Error())
					continue
				}

				fmt.Printf(" True transaction to fabric: %s\n", event.Key)
			} else {
				fmt.Printf("did not vote for true: %s\n", event.Key)
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

// config for validation vote
func makeValidationConfig() *sdnsOldCfg.Config {
	log.Root().SetHandler(log.LvlFilterHandler(0, log.StdoutHandler))

	cfg := new(sdnsOldCfg.Config)
	cfg.RootServers = []string{"192.5.5.241:53", "198.41.0.4:53",
		"192.228.79.201:53",
		"192.33.4.12:53",
		"199.7.91.13:53",
		"192.203.230.10:53",
		"192.112.36.4:53",
		"128.63.2.53:53",
		"192.36.148.17:53",
		"192.58.128.30:53",
		"193.0.14.129:53",
		"199.7.83.42:53",
		"202.12.27.33:53"}
	cfg.RootKeys = []string{
		".			172800	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
	}
	cfg.Maxdepth = 30
	cfg.Expire = 600
	cfg.CacheSize = 0
	cfg.Timeout.Duration = 2 * time.Second

	return cfg
}
