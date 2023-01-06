package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/domainr/dnsr"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/spf13/viper"

	sdnsCfg "github.com/semihalev/sdns/config"
)

const (
	ConfigFile     = "connection.yaml"
	DefaultProfile = "dev"
)

var fabCon = false

// var contract *gateway.Contract
var currentProfile string
var clientID []byte

var chainConfig sdnsCfg.ChainCfg

var validation_resolver = dnsr.New(0)

type FabricService struct {
	Gateway  *gateway.Gateway
	Network  *gateway.Network
	Contract *gateway.Contract
}

// fabric createRR event
type validationEvent struct {
	TxID       string   `json:"txid"`
	Validators []string `json:"validators"`
	Query      string   `json:"query"`
	Item       string   `json:"item"`
}

type votingEvent struct {
	VoterID string `json:"voterID"`
	Result  string `json:"result"`
}

type verifyresult struct {
	Result      string   `json:"result"`
	Update_txid []string `json:"update_txid"`
}

func (f *FabricService) getType() string {
	return "Fabric"
}

func (f *FabricService) Call(name string, args ...string) ([]byte, error) {
	response, err := f.Contract.EvaluateTransaction(name, args...)
	return response, err
}

func (f *FabricService) SendTransaction(name string, args ...string) ([]byte, error) {
	response, err := f.Contract.SubmitTransaction(name, args...)
	return response, err
}

func (f *FabricService) GetContract() *gateway.Contract {
	return f.Contract
}

// 连接Fabric，返回*gateway.Contract
func (f *FabricService) LoadConfig(confs ...string) error {

	os.Setenv("DISCOVERY_AS_LOCALHOST", "true")

	chainConfig = ReadChainCfg()

	fabCon = chainConfig.FabCon

	wallet, err := gateway.NewFileSystemWallet("wallet")
	if err != nil {
		log.Error("failed to create wallet", "error", err.Error())
		return err
	}

	if !wallet.Exists(chainConfig.UserName) {
		err = populateWallet(wallet)
		if err != nil {
			log.Error("failed to populate wallet contents", "error", err.Error())
			return err
		}
	}

	ccpPath := chainConfig.ConPath

	gw, err := gateway.Connect(
		gateway.WithConfig(config.FromFile(filepath.Clean(ccpPath))),
		gateway.WithIdentity(wallet, chainConfig.UserName),
	)
	if err != nil {
		log.Error("failed to connect to gateway", "error", err.Error())
		return err
	}

	log.Info("channel", chainConfig.Channel)
	network, err := gw.GetNetwork(chainConfig.Channel)
	if err != nil {
		log.Error("failed to get network", "error", err.Error())
		return err
	}

	contract := network.GetContract(chainConfig.ChaincodeDIS)

	// register identity
	clientID, err = contract.SubmitTransaction("CreateID")
	if err != nil {
		log.Error("failed to submit CreateID transaction to fabric ", "error", err.Error())
		return err
	}
	log.Info("successfully register ID", "clientID", string(clientID))

	// register fabric CreateRR event
	_, notifier, err := contract.RegisterEvent("validation")
	if err != nil {
		fmt.Printf("Failed to register contract event: %s", err)
		return err
	}
	// defer contract.Unregister(reg)

	// consume event and vote for validation
	go func() {
		for e := range notifier {

			event := new(validationEvent)
			err := json.Unmarshal(e.Payload, event)
			if err != nil {
				fmt.Println("failed to unmarshal", "event", string(e.Payload), "error", err.Error())
				continue
			}

			// Judge the event
			var found bool
			for _, client := range event.Validators {

				if string(clientID) == client {
					found = true
					break
				}
			}

			if !found {
				continue
			}

			fmt.Printf("Receive cc event, ccid: %v \neventName: %v\n"+
				"payload: %v \ntxid: %v \nblock: %v \nsourceURL: %v\n",
				e.ChaincodeID, e.EventName, string(e.Payload), e.TxID, e.BlockNumber, e.SourceURL)

			itemAsBytes := []byte(event.Item)

			fabricItem := new(FabricItem)
			err = json.Unmarshal(itemAsBytes, fabricItem)
			if err != nil {
				fmt.Println("failed to unmarshal", "fabricitem", string(itemAsBytes), "error", err.Error())
				continue
			}

			// ----TODO: 查询验证------
			var q *Question
			err = json.Unmarshal([]byte(event.Query), q)
			if err != nil {
				fmt.Println("failed to unmarshal", "qustion", event.Query, "error", err.Error())
			}

			req := new(dns.Msg)
			req.SetQuestion(q.Name, q.Qtype)

			resp, err := dns.Exchange(req, "127.0.0.1:"+chainConfig.Bind)
			if err != nil {
				fmt.Println("query validation failed", "req", req.String())
			}
			fmt.Println("successfully query validation", "resp", resp.String())

			query := event.Query
			verify_answer := resp.Answer
			original_answer := fabricItem.Answer

			result, _ := compareAnswer(original_answer, verify_answer)
			if result == "true" {
				_, err = contract.SubmitTransaction("Vote", query, event.TxID, "yes")
				if err != nil {
					fmt.Printf("failed to submit VoteTrue transaction to fabric: %s", err.Error())
					continue
				}

				fmt.Printf("Successfully Submit VoteTrue transaction to fabric: %s\n", event.TxID)
			} else {
				_, err = contract.SubmitTransaction("Vote", query, event.TxID, "no")
				if err != nil {
					fmt.Printf("failed to submit VoteFalse transaction to fabric: %s", err.Error())
					continue
				}

				fmt.Printf("Successfully Submit VoteFalse transaction to fabric: %s\n", event.TxID)
			}

		}
	}()

	f.Gateway = gw
	f.Network = network
	f.Contract = contract

	return nil
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

// -------TODO: 目前匹配方法只针对A或者AAAA记录查询，并且只匹配超过三分之一相同就行
func compareAnswer(str1 []RR, str2 []dns.RR) (string, error) {
	var ip_str1 []string
	var ip_str2 []string

	for _, v := range str1 {
		if v.Type == dns.TypeA || v.Type == dns.TypeAAAA {
			ip_str1 = append(ip_str1, v.Data)
		}

	}

	for _, v := range str2 {
		if v.Header().Rrtype == dns.TypeA || v.Header().Rrtype == dns.TypeAAAA {
			ip_str2 = append(ip_str2, strings.TrimPrefix(v.String(), v.Header().String()))
		}
	}

	if len(ip_str1) == 0 && len(ip_str2) == 0 {
		return "true", nil
	} else if len(ip_str1) == 0 || len(ip_str2) == 0 {
		return "false", nil
	}

	m := make(map[string]byte)
	var inter int

	for _, v := range ip_str1 {
		m[v] = 0
	}

	for _, v := range ip_str2 {
		if _, ok := m[v]; ok {
			inter++
		}
	}

	// 判断相同记录数量
	if inter < int(math.Ceil(float64(len(ip_str1))/3)) && inter < int(math.Ceil(float64(len(ip_str2))/3)) {
		log.Info(" compareAnswer: records are not euqal", ip_str1, ip_str2)

		return "false", nil
	} else {
		return "true", nil
	}

}
