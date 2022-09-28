package cache

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
	"github.com/semihalev/log"
)

var fabCon = true
var contract *gateway.Contract

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

// // 连接Fabric，返回*gateway.Contract
// func ConnectFab() *gateway.Contract {
// 	os.Setenv("DISCOVERY_AS_LOCALHOST", "true")
// 	wallet, err := gateway.NewFileSystemWallet("wallet")
// 	if err != nil {
// 		log.Error("failed to create wallet", "error", err.Error())
// 		return nil
// 	}

// 	if !wallet.Exists("resUser") {
// 		err = populateWallet(wallet)
// 		if err != nil {
// 			log.Error("failed to populate wallet contents", "error", err.Error())
// 			return nil
// 		}
// 	}

// 	gw, err := gateway.Connect(
// 		gateway.WithConfig(config.FromFile(filepath.Clean(ccpPath))),
// 		gateway.WithIdentity(wallet, "resUser"),
// 	)
// 	if err != nil {
// 		log.Error("failed to connect to gateway", "error", err.Error())
// 		return nil
// 	}

// 	network, err := gw.GetNetwork("mychannel")
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

// 	identity := gateway.NewX509Identity("Org1MSP", string(cert), string(key))

// 	err = wallet.Put("resUser", identity)
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

var credPath = filepath.Join(
	"/home",
	"fuxi",
	"dis-fabric",
	"data",
	"organizations",
	"peerOrganizations",
	"org-alpha",
	"admin",
	"msp",
)

var ccpPath = filepath.Join(
	"./",
	"config",
	"connection.yaml",
)

// 连接Fabric，返回*gateway.Contract
func ConnectFab() *gateway.Contract {
	os.Setenv("DISCOVERY_AS_LOCALHOST", "false")
	wallet, err := gateway.NewFileSystemWallet("wallet")
	if err != nil {
		log.Error("failed to create wallet", "error", err.Error())
		return nil
	}

	if !wallet.Exists("dis-resolver-admin-user") {
		err = populateWallet(wallet)
		if err != nil {
			log.Error("failed to populate wallet contents", "error", err.Error())
			return nil
		}
	}

	gw, err := gateway.Connect(
		gateway.WithConfig(config.FromFile(filepath.Clean(ccpPath))),
		gateway.WithIdentity(wallet, "dis-resolver-admin-user"),
	)
	if err != nil {
		log.Error("failed to connect to gateway", "error", err.Error())
		return nil
	}

	network, err := gw.GetNetwork("dis-channel")
	if err != nil {
		log.Error("failed to get network", "error", err.Error())
		return nil
	}

	contract := network.GetContract("dis_resolver")
	return contract
}

// 创建钱包用户resUser
func populateWallet(wallet *gateway.Wallet) error {

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

	identity := gateway.NewX509Identity("org-alpha-msp", string(cert), string(key))

	err = wallet.Put("dis-resolver-admin-user", identity)
	if err != nil {
		return err
	}
	return nil
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
