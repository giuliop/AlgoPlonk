// package algosdkwrapper provides utility functions to interact with an Algorand
// local network wrapping the go-algorand-sdk.
package algosdkwrapper

import (
	"fmt"
	"log"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/client/kmd"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/indexer"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
)

// default parameters for the local network, override them if needed
var (
	ALGOD_URL   = "http://localhost:4001"
	ALGOD_TOKEN = strings.Repeat("a", 64)

	INDEXER_URL   = "http://localhost:8980"
	INDEXER_TOKEN = strings.Repeat("a", 64)

	KMD_URL   = "http://localhost:4002"
	KMD_TOKEN = strings.Repeat("a", 64)

	KMD_WALLET_NAME     = "unencrypted-default-wallet"
	KMD_WALLET_PASSWORD = ""
)

func GetAlgodClient() *algod.Client {
	algodClient, err := algod.MakeClient(
		ALGOD_URL,
		ALGOD_TOKEN,
	)
	if err != nil {
		log.Fatalf("Failed to create algod client: %s", err)
	}
	return algodClient
}

func GetKmdClient() kmd.Client {
	kmdClient, err := kmd.MakeClient(
		KMD_URL,
		KMD_TOKEN,
	)
	if err != nil {
		log.Fatalf("Failed to create kmd client: %s", err)
	}
	return kmdClient
}

func GetIndexerClient() *indexer.Client {
	indexerClient, err := indexer.MakeClient(
		INDEXER_URL,
		INDEXER_TOKEN,
	)
	if err != nil {
		log.Fatalf("Failed to create indexer client: %s", err)
	}
	return indexerClient
}

func GetSandboxAccounts() ([]crypto.Account, error) {
	client := GetKmdClient()

	resp, err := client.ListWallets()
	if err != nil {
		return nil, fmt.Errorf("failed to list wallets: %+v", err)
	}

	var walletId string
	for _, wallet := range resp.Wallets {
		if wallet.Name == KMD_WALLET_NAME {
			walletId = wallet.ID
		}
	}

	if walletId == "" {
		return nil, fmt.Errorf("no wallet named %s", KMD_WALLET_NAME)
	}

	whResp, err := client.InitWalletHandle(walletId, KMD_WALLET_PASSWORD)
	if err != nil {
		return nil, fmt.Errorf("failed to init wallet handle: %+v", err)
	}

	addrResp, err := client.ListKeys(whResp.WalletHandleToken)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %+v", err)
	}

	var accts []crypto.Account
	for _, addr := range addrResp.Addresses {
		expResp, err := client.ExportKey(whResp.WalletHandleToken, KMD_WALLET_PASSWORD, addr)
		if err != nil {
			return nil, fmt.Errorf("failed to export key: %+v", err)
		}

		acct, err := crypto.AccountFromPrivateKey(expResp.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create account from private key: %+v", err)
		}

		accts = append(accts, acct)
	}

	return accts, nil
}
