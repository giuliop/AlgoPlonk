// package algosdkwrapper provides utility functions to interact with an Algorand
// local network wrapping the go-algorand-sdk.
package algosdkwrapper

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/client/kmd"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/indexer"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
)

// default parameters for algokit local network.
// Override them if needed, for instance by using the SetDevNet func below
var (
	algodURL   = "http://localhost:4001"
	algodToken = strings.Repeat("a", 64)

	indexerURL   = "http://localhost:8980"
	indexerToken = strings.Repeat("a", 64)

	kmdURL   = "http://localhost:4002"
	kmdToken = strings.Repeat("a", 64)

	kmdWalletName     = "unencrypted-default-wallet"
	kmdWalletPassword = ""
)

func init() {
	// uncomment the line below to use a custom devnet network
	// SetDevNet(filepath.Join(os.Getenv("HOME"), "dev/algorand/devnet/network/data"))
}

// setDevNet sets the default parameters for alogd and kmd to a local devnet
// network with node running at dir
func SetDevNet(dir string) {
	algodTokenBytes, err := os.ReadFile(filepath.Join(dir, "algod.token"))
	if err != nil {
		log.Fatalf("failed to read algod.token: %s", err)
	}
	algodToken = strings.TrimSpace(string(algodTokenBytes))

	algodURLBytes, err := os.ReadFile(filepath.Join(dir, "algod.net"))
	if err != nil {
		log.Fatalf("failed to read algod.net: %s", err)
	}
	algodURL = fmt.Sprintf("http://%s", strings.TrimSpace(string(algodURLBytes)))

	kmdURLBytes, err := os.ReadFile(filepath.Join(dir, "kmd.net"))
	kmdURL = fmt.Sprintf("http://%s", strings.TrimSpace(string(kmdURLBytes)))
	if err != nil {
		kmdURL = "http://localhost:7833"
	}

	kmdDir := dir + "/kmd-v0.5"
	kmdTokenBytes, err := os.ReadFile(filepath.Join(kmdDir, "kmd.token"))
	if err != nil {
		log.Fatalf("failed to read kmd.token: %s", err)
	}
	kmdToken = strings.TrimSpace(string(kmdTokenBytes))

	// run kmd
	cmd := exec.Command("goal", "kmd", "start", "-d", dir)
	if err := cmd.Run(); err != nil {
		log.Fatalf("failed to start kmd: %s", err)
	}
}

func GetAlgodClient() *algod.Client {
	algodClient, err := algod.MakeClient(
		algodURL,
		algodToken,
	)
	if err != nil {
		log.Fatalf("Failed to create algod client: %s", err)
	}
	return algodClient
}

func GetKmdClient() kmd.Client {
	kmdClient, err := kmd.MakeClient(
		kmdURL,
		kmdToken,
	)
	if err != nil {
		log.Fatalf("Failed to create kmd client: %s", err)
	}
	return kmdClient
}

func GetIndexerClient() *indexer.Client {
	indexerClient, err := indexer.MakeClient(
		indexerURL,
		indexerToken,
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
		if wallet.Name == kmdWalletName {
			walletId = wallet.ID
		}
	}

	if walletId == "" {
		return nil, fmt.Errorf("no wallet named %s", kmdWalletName)
	}

	whResp, err := client.InitWalletHandle(walletId, kmdWalletPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to init wallet handle: %+v", err)
	}

	addrResp, err := client.ListKeys(whResp.WalletHandleToken)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %+v", err)
	}

	var accts []crypto.Account
	for _, addr := range addrResp.Addresses {
		expResp, err := client.ExportKey(whResp.WalletHandleToken, kmdWalletPassword, addr)
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
