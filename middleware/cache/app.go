package cache

// import (
// 	"bytes"
// 	"context"
// 	"encoding/json"
// 	"fmt"
// 	"time"

// 	"github.com/hyperledger/fabric-gateway/pkg/client"
// 	"github.com/semihalev/log"
// )

// const (
// 	channelName   = "mychannel"
// 	chaincodeName = "dis_resolver"
// )

// // var now = time.Now()

// // var assetID = fmt.Sprintf("asset%d", now.Unix()*1e3+int64(now.Nanosecond())/1e6)

// func connectFab() *client.Contract {
// 	clientConnection := newGrpcConnection()
// 	// defer clientConnection.Close()

// 	id := newIdentity()
// 	sign := newSign()

// 	gateway, err := client.Connect(
// 		id,
// 		client.WithSign(sign),
// 		client.WithClientConnection(clientConnection),
// 		client.WithEvaluateTimeout(5*time.Second),
// 		client.WithEndorseTimeout(15*time.Second),
// 		client.WithSubmitTimeout(5*time.Second),
// 		client.WithCommitStatusTimeout(1*time.Minute),
// 	)
// 	if err != nil {
// 		panic(err)
// 	}
// 	// defer gateway.Close()

// 	network := gateway.GetNetwork(channelName)
// 	contract := network.GetContract(chaincodeName)

// 	// Context used for event listening
// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()

// 	// Listen for events emitted by subsequent transactions
// 	startChaincodeEventListening(ctx, network)

// 	return contract
// }

// func startChaincodeEventListening(ctx context.Context, network *client.Network) {
// 	fmt.Println("\n*** Start chaincode event listening")

// 	events, err := network.ChaincodeEvents(ctx, chaincodeName)
// 	if err != nil {
// 		panic(fmt.Errorf("failed to start chaincode event listening: %w", err))
// 	}

// 	go func() {
// 		// fmt.Println("--------")
// 		// for event := range events {
// 		// 	log.Info("event", event.EventName)
// 		// 	log.Info("event", event.Payload)
// 		// 	asset := formatJSON(event.Payload)
// 		// 	fmt.Printf("\n<-- Chaincode event received: %s - %s\n", event.EventName, asset)
// 		// }
// 		// fmt.Println("=======")

// 		for {
// 			select {
// 			// case <-time.After(10 * time.Second):
// 			// 	panic(errors.New("timeout waiting for event replay"))

// 			case event := <-events:
// 				// asset := formatJSON(event.Payload)
// 				fmt.Printf("\n<-- Chaincode event received: %s - %s\n", event.EventName, "s")

// 				if event.EventName == "DeleteAsset" {
// 					// Reached the last submitted transaction so return to stop listening for events
// 					return
// 				}
// 			}
// 		}
// 	}()
// }

// func formatJSON(data []byte) string {
// 	var result bytes.Buffer
// 	if err := json.Indent(&result, data, "", "  "); err != nil {
// 		panic(fmt.Errorf("failed to parse JSON: %w", err))
// 	}
// 	return result.String()
// }

// func (i *FabricItem) setRR(key string) {
// 	itemAsBytes, err := json.Marshal(i)
// 	if err != nil {
// 		log.Error("failed to set RR in fabric cache : failed to marshal", "error", err.Error())
// 	}

// 	_, err = contract.SubmitTransaction("CreateRR", key, string(itemAsBytes))
// 	if err != nil {
// 		log.Info("failed to submit CreateRR transaction to fabric ", "error", err.Error())
// 	}

// }
